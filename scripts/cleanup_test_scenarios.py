"""Delete findings + detections + campaigns tagged as test scenarios.

Usage: python scripts/cleanup_test_scenarios.py [--yes]
"""
import argparse
import asyncio
import sys

from sqlalchemy import delete, select

from ati_evn.db.models import Campaign, CampaignFinding, Detection, Finding
from ati_evn.db.session import async_session


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    async with async_session() as session:
        f_stmt = select(Finding.id).where(
            Finding.metadata_.op("->>")("test_scenario") == "true"
        )
        f_ids = list((await session.execute(f_stmt)).scalars())

        d_stmt = select(Detection.id).where(
            Detection.metadata_.op("->>")("test_scenario") == "true"
        )
        d_ids = list((await session.execute(d_stmt)).scalars())

        print(f"Would delete: {len(f_ids)} findings, {len(d_ids)} detections")
        print("Would delete campaigns linked to any test finding.")

        if not args.yes:
            print("\nRe-run with --yes to actually delete.")
            return

        # Delete campaigns whose findings are test
        if f_ids:
            await session.execute(
                delete(Campaign).where(
                    Campaign.id.in_(
                        select(CampaignFinding.campaign_id).where(
                            CampaignFinding.finding_id.in_(f_ids)
                        )
                    )
                )
            )
            await session.execute(delete(Finding).where(Finding.id.in_(f_ids)))
        if d_ids:
            await session.execute(delete(Detection).where(Detection.id.in_(d_ids)))
        await session.commit()
        print("Cleanup complete.")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
