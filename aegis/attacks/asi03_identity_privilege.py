"""ASI03: Identity and privilege abuse attack module."""
from __future__ import annotations

from collections import defaultdict

from aegis.attacks.base import BaseAttackModule
from aegis.campaigns.runner import CampaignRunner, CampaignTurn
from aegis.interfaces.agent import AgentInterface
from aegis.models import AttackPayload, AttackResult


class IdentityPrivilegeModule(BaseAttackModule):
    """Exercise identity spoofing, delegation abuse, and privilege escalation chains."""

    name = "asi03_identity_privilege"
    owasp_id = "ASI03"
    atlas_technique = None
    description = (
        "Tests delegation-chain abuse, identity spoofing, token theft, and cross-agent "
        "privilege escalation coverage in AEGIS v2."
    )
    category = "Identity and Privilege Abuse"
    default_severity = "high"
    supports_multi_turn = True
    max_turns = 3

    def execute(self, agent: AgentInterface) -> list[AttackResult]:
        """Run payloads as linear campaigns grouped by campaign_id metadata."""
        if self._payloads is None:
            msg = "No payloads loaded. Call generate_payloads() before execute()."
            raise RuntimeError(msg)

        runner = CampaignRunner()
        results: list[AttackResult] = []

        for campaign_id, payloads in _payload_campaigns(self._payloads).items():
            agent.reset()
            turns = [
                CampaignTurn(
                    turn_id=payload.id,
                    payload=payload,
                    context={
                        "campaign_id": campaign_id,
                        "technique": payload.metadata.get("technique"),
                    },
                )
                for payload in payloads
            ]
            campaign_result = runner.run(
                agent=agent,
                turns=turns,
                campaign_id=f"{self.name}:{campaign_id}",
                max_turns=self.max_turns,
            )
            results.extend(campaign_result.results)

        return results


def _payload_campaigns(payloads: list[AttackPayload]) -> dict[str, list[AttackPayload]]:
    grouped: dict[str, list[AttackPayload]] = defaultdict(list)
    for payload in payloads:
        campaign_id = str(payload.metadata.get("campaign_id", payload.id))
        grouped[campaign_id].append(payload)

    return {
        campaign_id: sorted(
            items,
            key=lambda payload: int(payload.metadata.get("turn_index", 0)),
        )
        for campaign_id, items in grouped.items()
    }
