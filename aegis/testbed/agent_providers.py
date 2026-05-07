"""Provider selection, health checks, and LLM call dispatch mixin for DefaultAgent."""
from __future__ import annotations

import importlib
import json
import logging
import os
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from aegis.optional_dependencies import missing_dependency_error
from aegis.testbed.retry import call_with_retry

logger = logging.getLogger(__name__)

_HOSTED_PROVIDER_MODES: frozenset[str] = frozenset({
    "openai_compat",
    "anthropic",
    "hf_inference",
})


class _AgentProvidersMixin:
    """Mixin: provider selection, health checks, and LLM calls."""

    def _select_provider(self) -> tuple[str, str]:
        provider_cfg = self._config.get("provider", {})
        mode = str(provider_cfg.get("mode", self._config.get("model_provider", "auto")))

        if mode == "offline":
            return "offline", "offline mode explicitly selected"
        if mode == "ollama":
            ollama_ok, ollama_note = self._check_ollama_health()
            if not ollama_ok:
                raise RuntimeError(f"Ollama provider requested but unavailable: {ollama_note}")
            return "ollama", ollama_note
        if mode == "huggingface":
            hf_ok, hf_note = self._check_hf_token(provider_cfg)
            if not hf_ok:
                raise RuntimeError(
                    f"HuggingFace provider requested but unavailable: {hf_note}"
                )
            return "huggingface", hf_note
        if mode in _HOSTED_PROVIDER_MODES:
            hosted_ok, hosted_note = self._check_hosted_provider_key(mode, provider_cfg)
            if not hosted_ok:
                raise RuntimeError(f"{mode} provider requested but unavailable: {hosted_note}")
            return mode, hosted_note

        ollama_ok, ollama_note = self._check_ollama_health()
        if ollama_ok:
            return "ollama", ollama_note
        hf_ok, hf_note = self._check_hf_token(provider_cfg)
        if hf_ok:
            return "huggingface", hf_note

        require_external = bool(provider_cfg.get("require_external", False))
        if require_external:
            raise RuntimeError(
                "No external provider is available. "
                f"Ollama: {ollama_note}; HuggingFace: {hf_note}"
            )
        return "offline", f"falling back to offline mode; ollama={ollama_note}; hf={hf_note}"

    def _check_hosted_provider_key(
        self,
        mode: str,
        provider_cfg: dict[str, Any],
    ) -> tuple[bool, str]:
        try:
            client = importlib.import_module(f"aegis.interfaces.{mode}")
            result = client.api_key_available(provider_cfg)
        except Exception as exc:
            return False, f"provider adapter unavailable: {exc}"

        if isinstance(result, tuple):
            available = bool(result[0])
            note = str(result[1]) if len(result) > 1 else ""
        else:
            available = bool(result)
            note = ""

        env_name = self._hosted_api_key_env(mode, provider_cfg)
        if not available:
            return False, note or f"missing env {env_name}"
        return True, note or f"API key found via {env_name}"

    def _hosted_api_key_env(self, mode: str, provider_cfg: dict[str, Any]) -> str:
        if provider_cfg.get("api_key_env"):
            return str(provider_cfg["api_key_env"])
        if mode == "openai_compat":
            return "OPENAI_API_KEY"
        if mode == "anthropic":
            return "ANTHROPIC_API_KEY"
        if mode == "hf_inference" and provider_cfg.get("hf_token_env"):
            return str(provider_cfg["hf_token_env"])
        if mode == "hf_inference":
            return "HF_TOKEN"
        return "PROVIDER_API_KEY"

    def _check_ollama_health(self) -> tuple[bool, str]:
        provider_cfg = self._config.get("provider", {})
        base_url = str(provider_cfg.get("ollama_base_url", "http://localhost:11434"))
        timeout_seconds = float(provider_cfg.get("ollama_health_timeout_seconds", 3))
        model = str(self._config.get("model", "qwen3:4b"))
        request = Request(f"{base_url.rstrip('/')}/api/tags", method="GET")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                if response.status != 200:
                    return False, f"HTTP {response.status}"
                body = json.loads(response.read())
        except URLError as exc:
            return False, str(exc.reason)
        except TimeoutError:
            return False, "timeout"
        except json.JSONDecodeError:
            return False, "invalid JSON from /api/tags"

        available = [m.get("name", "") for m in body.get("models", [])]
        if not any(model == name or name.startswith(f"{model}") for name in available):
            return False, f"model '{model}' not pulled; available: {available}"
        return True, f"model '{model}' present"

    def _check_hf_token(self, provider_cfg: dict[str, Any]) -> tuple[bool, str]:
        token_env = str(provider_cfg.get("hf_token_env", "HF_TOKEN"))
        token = os.getenv(token_env)
        if not token:
            return False, f"missing env {token_env}"

        request = Request("https://huggingface.co/api/whoami-v2", method="GET")
        request.add_header("Authorization", f"Bearer {token}")
        try:
            with urlopen(request, timeout=3) as response:
                if response.status != 200:
                    return False, f"token validation returned HTTP {response.status}"
        except URLError as exc:
            return False, str(exc.reason)
        except TimeoutError:
            return False, "token validation timeout"
        return True, f"token validated via {token_env}"

    def _retry_settings(self) -> tuple[float, int, float, float, float]:
        timeout_seconds = float(self._config.get("llm_timeout_seconds", 30))
        max_retries = int(self._config.get("llm_max_retries", 3))
        base_delay = float(self._config.get("llm_retry_base_delay_seconds", 0.5))
        max_delay = float(self._config.get("llm_retry_max_delay_seconds", 8.0))
        jitter = float(self._config.get("llm_retry_jitter_seconds", 0.25))
        return timeout_seconds, max_retries, base_delay, max_delay, jitter

    def _supports_model_tool_calling(self) -> bool:
        return self._provider_name == "ollama"

    def _build_tool_calling_model(self):
        if self._provider_name != "ollama":
            raise RuntimeError(
                f"Provider '{self._provider_name}' does not support model-driven tool calling."
            )
        try:
            from langchain_community.chat_models.ollama import ChatOllama
        except ImportError as exc:
            raise missing_dependency_error(
                feature="Ollama provider",
                extra="local",
                packages=["langchain", "langchain-community"],
            ) from exc

        provider_cfg = self._config.get("provider", {})
        model_name = str(self._config.get("model", "qwen3:4b"))
        timeout_seconds = int(
            float(
                provider_cfg.get(
                    "ollama_generate_timeout_seconds",
                    self._config.get("llm_timeout_seconds", 30),
                )
            )
        )
        num_predict = int(provider_cfg.get("ollama_num_predict", 128))
        keep_alive = str(provider_cfg.get("ollama_keep_alive", "15m"))
        return ChatOllama(
            model=model_name,
            base_url=str(provider_cfg.get("ollama_base_url", "http://localhost:11434")),
            timeout=timeout_seconds,
            num_predict=num_predict,
            keep_alive=keep_alive,
            temperature=0.0,
        )

    def _build_chat_messages(self, payload: Any) -> list:
        try:
            from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
        except ImportError as exc:
            raise missing_dependency_error(
                feature="LangChain tool execution",
                extra="local",
                packages=["langchain", "langchain-community"],
            ) from exc

        messages: list = []
        system_parts = ["You are the AEGIS target agent."]
        rag_lines = (
            list(self._kb_context_lines) if self._kb_context_lines else list(self._injected_rag)
        )
        if rag_lines:
            system_parts.append("Knowledge base context:")
            system_parts.extend(rag_lines)
        if self._memory:
            memory_text = "\n".join(
                f"{m.get('role', 'user')}: {m.get('content', '')}" for m in self._memory
            )
            system_parts.append(f"Memory:\n{memory_text}")
        messages.append(SystemMessage(content="\n".join(system_parts)))

        for msg in payload.messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                messages.append(SystemMessage(content=content))
            elif role == "assistant":
                messages.append(AIMessage(content=content))
            else:
                messages.append(HumanMessage(content=content))

        return messages

    def _call_ollama(self, prompt: str) -> str:
        provider_cfg = self._config.get("provider", {})
        model = str(self._config.get("model", "qwen3:4b"))
        base_url = str(provider_cfg.get("ollama_base_url", "http://localhost:11434")).rstrip("/")
        num_predict = int(provider_cfg.get("ollama_num_predict", 128))
        keep_alive = str(provider_cfg.get("ollama_keep_alive", "15m"))

        timeout_seconds, max_retries, base_delay, max_delay, jitter = self._retry_settings()
        timeout_seconds = float(
            provider_cfg.get("ollama_generate_timeout_seconds", timeout_seconds)
        )
        body = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "think": False,
            "stream": False,
            "keep_alive": keep_alive,
            "options": {"num_predict": num_predict},
        }).encode("utf-8")

        def _invoke() -> str:
            request = Request(
                f"{base_url}/api/chat",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON from Ollama /api/chat") from exc
            message = parsed.get("message", {})
            content = message.get("content", "")
            if not content:
                content = parsed.get("response", "")
            text = str(content).strip()
            if not text:
                raise ValueError("empty response from Ollama /api/chat")
            return text

        return call_with_retry(
            _invoke,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            base_delay_seconds=base_delay,
            max_delay_seconds=max_delay,
            jitter_seconds=jitter,
            operation_name="ollama_generate",
        )

    def _call_hf(self, prompt: str) -> str:
        try:
            from langchain_community.llms import HuggingFaceEndpoint
        except ImportError as exc:
            raise missing_dependency_error(
                feature="HuggingFace provider",
                extra="local",
                packages=["langchain", "langchain-community"],
            ) from exc

        provider_cfg = self._config.get("provider", {})
        token_env = str(provider_cfg.get("hf_token_env", "HF_TOKEN"))
        model = str(provider_cfg.get("hf_model", "HuggingFaceH4/zephyr-7b-beta"))

        timeout_seconds, max_retries, base_delay, max_delay, jitter = self._retry_settings()

        def _invoke() -> str:
            llm = HuggingFaceEndpoint(
                model=model,
                huggingfacehub_api_token=os.getenv(token_env),
                temperature=0.0,
                max_new_tokens=256,
            )
            output = llm.invoke(prompt)
            return str(output).strip() or "No response from HuggingFace model."

        return call_with_retry(
            _invoke,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            base_delay_seconds=base_delay,
            max_delay_seconds=max_delay,
            jitter_seconds=jitter,
            operation_name="hf_generate",
        )

    def _call_hosted_provider(self, prompt: str) -> str:
        if self._provider_name not in _HOSTED_PROVIDER_MODES:
            raise RuntimeError(f"Provider '{self._provider_name}' is not a hosted provider.")

        client = importlib.import_module(f"aegis.interfaces.{self._provider_name}")
        provider_cfg = dict(self._config.get("provider", {}))
        provider_cfg["model"] = str(provider_cfg.get("model") or self._config.get("model", ""))
        timeout_seconds, max_retries, base_delay, max_delay, jitter = self._retry_settings()
        timeout_seconds = float(provider_cfg.get("timeout_seconds", timeout_seconds))

        def _invoke() -> str:
            output = client.complete(prompt, provider_cfg)
            text = str(output).strip()
            if not text:
                raise ValueError(f"empty response from {self._provider_name}")
            return text

        return call_with_retry(
            _invoke,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            base_delay_seconds=base_delay,
            max_delay_seconds=max_delay,
            jitter_seconds=jitter,
            operation_name=f"{self._provider_name}_generate",
        )
