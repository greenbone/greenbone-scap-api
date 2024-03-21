# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import AliasGenerator, AnyUrl, ConfigDict, UrlConstraints
from pydantic import BaseModel as PydanticBaseModel
from pydantic.alias_generators import to_camel

DEFAULT_FORMAT = "NVD_CVE"
DEFAULT_VERSION = "2.0"


class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        alias_generator=AliasGenerator(
            serialization_alias=to_camel,
        ),
    )


class CVSSv2Data(BaseModel):
    vector_string: str
    version: str
    base_score: float
    access_vector: str | None
    access_complexity: str | None
    authentication: str | None
    confidentiality_impact: str | None
    integrity_impact: str | None
    availability_impact: str | None
    exploitability: str | None
    remediation_level: str | None
    report_confidence: str | None
    temporal_score: float | None
    collateral_damage_potential: str | None
    target_distribution: str | None
    confidentiality_requirement: str | None
    integrity_requirement: str | None
    availability_requirement: str | None
    environmental_score: float | None


class CVSSv2Metric(BaseModel):
    source: str
    type: str
    base_severity: str | None
    exploitability_score: float | None
    impact_score: float | None
    ac_insuf_info: bool | None
    obtain_all_privilege: bool | None
    obtain_user_privilege: bool | None
    obtain_other_privilege: bool | None
    user_interaction_required: bool | None

    cvss_data: CVSSv2Data


class CVSSv3Data(BaseModel):
    vector_string: str
    version: str
    base_score: float
    base_severity: str
    attack_vector: str | None
    attack_complexity: str | None
    privileges_required: str | None
    user_interaction: str | None
    scope: str | None
    confidentiality_impact: str | None
    integrity_impact: str | None
    availability_impact: str | None
    exploit_code_maturity: str | None
    remediation_level: str | None
    report_confidence: str | None
    temporal_score: float | None
    temporal_severity: str | None
    confidentiality_requirement: str | None
    integrity_requirement: str | None
    availability_requirement: str | None
    modified_attack_vector: str | None
    modified_attack_complexity: str | None
    modified_privileges_required: str | None
    modified_user_interaction: str | None
    modified_scope: str | None
    modified_confidentiality_impact: str | None
    modified_integrity_impact: str | None
    modified_availability_impact: str | None
    environmental_score: float | None
    environmental_severity: str | None


class CVSSv3Metric(BaseModel):
    source: str
    type: str
    exploitability_score: float | None
    impact_score: float | None

    cvss_data: CVSSv3Data


class Description(BaseModel):
    lang: str
    value: str


class VendorComment(BaseModel):
    organization: str
    comment: str
    last_modified: datetime


class Weakness(BaseModel):
    source: str
    type: str

    description: list[Description]


ReferenceUrl = Annotated[
    AnyUrl, UrlConstraints(allowed_schemes=["http", "https", "ftp", "ftps"])
]


class Reference(BaseModel):
    url: ReferenceUrl
    source: str | None
    tags: list[str]


class CPEMatch(BaseModel):
    vulnerable: bool
    match_criteria_id: UUID
    criteria: str
    version_start_excluding: str | None
    version_start_including: str | None
    version_end_excluding: str | None
    version_end_including: str | None


class OperatorEnum(StrEnum):
    AND = "AND"
    OR = "OR"


class Node(BaseModel):
    operator: OperatorEnum
    negate: bool | None

    cpe_match: list[CPEMatch]


class Configuration(BaseModel):
    operator: OperatorEnum | None
    negate: bool | None

    nodes: list[Node]


class Metrics(BaseModel):
    cvss_metric_v2: list[CVSSv2Metric]
    cvss_metric_v30: list[CVSSv3Metric]
    cvss_metric_v31: list[CVSSv3Metric]


class VulnStatus(StrEnum):
    REJECTED = "Rejected"
    ANALYZED = "Analyzed"
    AWAITING_ANALYSIS = "Awaiting Analysis"
    MODIFIED = "Modified"
    RECEIVED = "Received"
    Rejected = "Rejected"
    UNDERGOING_ANALYSIS = "Undergoing Analysis"


class CVE(BaseModel):
    id: str
    source_identifier: str
    vuln_status: str
    published: datetime
    last_modified: datetime
    evaluator_comment: str | None
    evaluator_solution: str | None
    evaluator_impact: str | None
    cisa_exploit_add: date | None
    cisa_action_due: date | None
    cisa_required_action: str | None
    cisa_vulnerability_name: str | None

    descriptions: list[Description]
    metrics: Metrics
    weaknesses: list[Weakness]
    configurations: list[Configuration]
    references: list[Reference]
    vendor_comments: list[VendorComment]


class CVEItem(BaseModel):
    cve: CVE


class CVEResponse(BaseModel):
    results_per_page: int
    start_index: int
    total_results: int
    format: str = DEFAULT_FORMAT
    version: str = DEFAULT_VERSION
    timestamp: datetime
    vulnerabilities: list[CVEItem]
