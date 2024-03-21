# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from typing import Iterable

from greenbone.scap.cve.manager import CVEManager
from greenbone.scap.cve.models import (
    CVEModel,
    CVSSv2MetricModel,
    CVSSv3MetricModel,
)

from .schema import (
    CVE,
    CVEItem,
    CVSSv2Data,
    CVSSv2Metric,
    CVSSv3Data,
    CVSSv3Metric,
    Metrics,
)


def _convert_cvss_v2(cvss: CVSSv2MetricModel) -> CVSSv2Metric:
    return CVSSv2Metric(
        source=cvss.source,
        type=cvss.type,
        base_severity=cvss.base_severity,
        exploitability_score=cvss.exploitability_score,
        impact_score=cvss.impact_score,
        ac_insuf_info=cvss.ac_insuf_info,
        obtain_all_privilege=cvss.obtain_all_privilege,
        obtain_other_privilege=cvss.obtain_other_privilege,
        obtain_user_privilege=cvss.obtain_user_privilege,
        user_interaction_required=cvss.user_interaction_required,
        cvss_data=CVSSv2Data(
            vector_string=cvss.vector_string,
            base_score=cvss.base_score,
            version=cvss.version,
            access_complexity=cvss.access_complexity,
            access_vector=cvss.access_vector,
            authentication=cvss.authentication,
            availability_impact=cvss.availability_impact,
            availability_requirement=cvss.availability_requirement,
            confidentiality_impact=cvss.confidentiality_impact,
            confidentiality_requirement=cvss.confidentiality_requirement,
            collateral_damage_potential=cvss.collateral_damage_potential,
            environmental_score=cvss.environmental_score,
            exploitability=cvss.exploitability,
            integrity_impact=cvss.integrity_impact,
            integrity_requirement=cvss.integrity_requirement,
            remediation_level=cvss.remediation_level,
            report_confidence=cvss.report_confidence,
            temporal_score=cvss.temporal_score,
            target_distribution=cvss.target_distribution,
        ),
    )


def _convert_cvss_v3(cvss: CVSSv3MetricModel) -> CVSSv3Metric:
    return CVSSv3Metric(
        source=cvss.source,
        type=cvss.type,
        exploitability_score=cvss.exploitability_score,
        impact_score=cvss.impact_score,
        cvss_data=CVSSv3Data(
            attack_complexity=cvss.attack_complexity,
            attack_vector=cvss.attack_vector,
            availability_impact=cvss.availability_impact,
            availability_requirement=cvss.availability_requirement,
            base_score=cvss.base_score,
            base_severity=cvss.base_severity,
            vector_string=cvss.vector_string,
            version=cvss.version,
            scope=cvss.scope,
            confidentiality_impact=cvss.confidentiality_impact,
            confidentiality_requirement=cvss.confidentiality_requirement,
            environmental_score=cvss.environmental_score,
            environmental_severity=cvss.environmental_severity,
            privileges_required=cvss.privileges_required,
            user_interaction=cvss.user_interaction,
            integrity_impact=cvss.integrity_impact,
            integrity_requirement=cvss.integrity_requirement,
            exploit_code_maturity=cvss.exploit_code_maturity,
            modified_attack_complexity=cvss.modified_attack_complexity,
            modified_attack_vector=cvss.modified_attack_vector,
            modified_availability_impact=cvss.modified_availability_impact,
            modified_confidentiality_impact=cvss.modified_confidentiality_impact,
            modified_integrity_impact=cvss.modified_integrity_impact,
            modified_privileges_required=cvss.modified_privileges_required,
            modified_scope=cvss.modified_scope,
            modified_user_interaction=cvss.modified_user_interaction,
            remediation_level=cvss.remediation_level,
            report_confidence=cvss.report_confidence,
            temporal_score=cvss.temporal_score,
            temporal_severity=cvss.temporal_severity,
        ),
    )


def _convert_cve(cve: CVEModel) -> CVE:
    return CVE(
        id=cve.id,
        source_identifier=cve.source_identifier,
        published=cve.published,
        last_modified=cve.last_modified,
        vuln_status=cve.vuln_status,
        evaluator_comment=cve.evaluator_comment,
        evaluator_solution=cve.evaluator_solution,
        evaluator_impact=cve.evaluator_impact,
        cisa_exploit_add=cve.cisa_exploit_add,
        cisa_action_due=cve.cisa_action_due,
        cisa_required_action=cve.cisa_required_action,
        cisa_vulnerability_name=cve.cisa_vulnerability_name,
        metrics=Metrics(
            cvss_metric_v2=[
                _convert_cvss_v2(cvss) for cvss in cve.cvss_metrics_v2
            ],
            cvss_metric_v30=[
                _convert_cvss_v3(cvss) for cvss in cve.cvss_metrics_v30
            ],
            cvss_metric_v31=[
                _convert_cvss_v3(cvss) for cvss in cve.cvss_metrics_v31
            ],
        ),
        configurations=cve.configurations,
        descriptions=cve.descriptions,
        references=cve.references,
        vendor_comments=cve.vendor_comments,
        weaknesses=cve.weaknesses,
    )


async def get_cve_items(
    manager: CVEManager,
    limit: int,
    index: int,
    cve_id: str | None,
    last_modification_start_date: datetime | None = None,
    last_modification_end_date: datetime | None = None,
    published_start_date: datetime | None = None,
    published_end_date: datetime | None = None,
    source_identifier: str | None = None,
    no_rejected: bool | None = None,
    keywords: Iterable[str] | str | None = None,
    cwe_id: str | None = None,
    cvss_v2_vector: str | None = None,
    cvss_v3_vector: str | None = None,
    cvss_v2_severity: str | None = None,
    cvss_v3_severity: str | None = None,
) -> list[CVEItem]:
    return [
        CVEItem(cve=_convert_cve(cve))
        async for cve in manager.find(
            limit=limit,
            index=index,
            cve_ids=cve_id,
            last_modification_start_date=last_modification_start_date,
            last_modification_end_date=last_modification_end_date,
            published_start_date=published_start_date,
            published_end_date=published_end_date,
            source_identifier=source_identifier,
            no_rejected=no_rejected,
            keywords=keywords,
            cwe_id=cwe_id,
            cvss_v2_vector=cvss_v2_vector,
            cvss_v3_vector=cvss_v3_vector,
            cvss_v2_severity=cvss_v2_severity,
            cvss_v3_severity=cvss_v3_severity,
        )
    ]
