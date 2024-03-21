# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from .data import get_cve_items
from .dependencies import CVEManagerDependency
from .schema import CVEResponse

router = APIRouter()

MAX_RESULTS_PER_PAGE = 2000
DEFAULT_RESULTS_PER_PAGE = 2000

RESULTS_PER_PAGE_DESCRIPTION = (
    "This parameter specifies the **maximum number of CVE records** to be returned "
    f"in a single API response. The default value is {DEFAULT_RESULTS_PER_PAGE} "
    f"and maximum allowable limit is {MAX_RESULTS_PER_PAGE}. "
)
START_INDEX_DESCRIPTION = (
    "This parameter specifies the **index of the first CVE** to be returned in the "
    "response data. The index is zero-based, meaning the first CVE is at index "
    "zero."
)
CVE_ID_DESCRIPTION = (
    "This parameter returns a specific vulnerability identified by its unique "
    "**Common Vulnerabilities and Exposures identifier** (the **CVE ID**)."
)
LAST_MODIFICATION_START_DATE_DESCRIPTION = (
    "These parameters return only the CVEs that were **last modified after** "
    "(including) `lastModStartDate`."
)
LAST_MODIFICATION_END_DATE_DESCRIPTION = (
    "These parameters return only the CVEs that were **last modified before** "
    "(including) `lastModEndDate`."
)
PUBLISHED_START_DATE_DESCRIPTION = (
    "These parameters return only the CVEs that were **added** to the NVD (i.e., "
    "published) **after** (including) `pubStartDate`."
)
PUBLISHED_END_DATE_DESCRIPTION = (
    "These parameters return only the CVEs that were **added** to the NVD (i.e., "
    "published) **before** (including) `pubEndDate`."
)
SOURCE_IDENTIFIER_DESCRIPTION = (
    "This parameter returns CVE where the exact value of `sourceIdentifier` "
    "appears as a **data source** in the CVE record."
)
NO_REJECTED_DESCRIPTION = (
    "By default, the CVE API includes CVE records with the `REJECT` or Rejected "
    "status. This parameter **excludes** CVE records with the `REJECT` or Rejected "
    "status from API response. "
)
KEYWORD_SEARCH_DESCRIPTION = (
    "This parameter returns only the CVEs where a **word or phrase** is found in "
    "the current **description**. Multiple keywords function like an *AND* "
    "statement. This returns results where all keywords exist somewhere in the "
    "current description, though not necessarily together. Keyword search "
    "operates as though a wildcard is placed after each keyword provided. For "
    "example, providing *circle* will return results such as *circles* but "
    "not *encircle*. The matching of keywords is case insensitive. *CiRcLe* "
    "will match *circle*, *CIRCLE* and all other variations in between."
)
KEYWORD_EXACT_MATCH_DESCRIPTION = (
    "By default, `keywordSearch` returns any CVE where a word or phrase is found "
    "in the current description. If the value of `keywordSearch` is a phrase, "
    "i.e., contains more than one term, including `keywordExactMatch` returns "
    "only the **CVEs matching the phrase exactly**. Otherwise, the results will "
    "contain records having any of the terms. If `keywordSearch` is not set, "
    "`keywordExactMatch` will be ignored."
)
CWE_ID_DESCRIPTION = (
    "This parameter returns only the CVE that include a weakness identified by "
    "**Common Weakness Enumeration** using the provided CWE-ID."
)
CVSS_V2_VECTOR_DESCRIPTION = (
    "This parameter returns only the CVEs that match the provided **CVSSv2 "
    "vector**. Either full or partial vector strings may be used."
)
CVSS_V3_VECTOR_DESCRIPTION = (
    "This parameter returns only the CVEs that match the provided **CVSSv3 "
    "vector**. Either full or partial vector strings may be used."
)
CVSS_V2_SEVERITY_DESCRIPTION = (
    "This parameter returns only the CVEs that match the provided **CVSSv2 "
    "qualitative severity rating**. Values can be `LOW`, `MEDIUM` or `HIGH`."
)
CVSS_V3_SEVERITY_DESCRIPTION = (
    "This parameter returns only the CVEs that match the provided **CVSSv3 "
    "qualitative severity rating**. Values can be `LOW`, `MEDIUM`, `HIGH` and "
    "`CRITICAL`."
)


@router.get(
    "/cves",
    response_model_exclude_none=True,
    response_model_exclude_defaults=False,
)
async def cves(
    *,
    results_per_page: Annotated[
        int,
        Query(
            alias="resultsPerPage",
            ge=1,
            le=MAX_RESULTS_PER_PAGE,
            description=RESULTS_PER_PAGE_DESCRIPTION,
        ),
    ] = DEFAULT_RESULTS_PER_PAGE,
    start_index: Annotated[
        int,
        Query(alias="startIndex", ge=0, description=START_INDEX_DESCRIPTION),
    ] = 0,
    cve_id: Annotated[
        str | None, Query(alias="cveId", description=CVE_ID_DESCRIPTION)
    ] = None,
    last_modification_start_date: Annotated[
        datetime | None,
        Query(
            alias="lastModStartDate",
            description=LAST_MODIFICATION_START_DATE_DESCRIPTION,
        ),
    ] = None,
    last_modification_end_date: Annotated[
        datetime | None,
        Query(
            alias="lastModEndDate",
            description=LAST_MODIFICATION_END_DATE_DESCRIPTION,
        ),
    ] = None,
    published_start_date: Annotated[
        datetime | None,
        Query(
            alias="pubStartDate", description=PUBLISHED_START_DATE_DESCRIPTION
        ),
    ] = None,
    published_end_date: Annotated[
        datetime | None,
        Query(alias="pubEndDate", description=PUBLISHED_END_DATE_DESCRIPTION),
    ] = None,
    source_identifier: Annotated[
        str | None,
        Query(
            alias="sourceIdentifier", description=SOURCE_IDENTIFIER_DESCRIPTION
        ),
    ] = None,
    no_rejected: Annotated[
        str | None,
        Query(alias="noRejected", description=NO_REJECTED_DESCRIPTION),
    ] = None,
    keyword_search: Annotated[
        str | None,
        Query(alias="keywordSearch", description=KEYWORD_SEARCH_DESCRIPTION),
    ] = None,
    keyword_exact_match: Annotated[
        str | None,
        Query(
            alias="keywordExactMatch",
            description=KEYWORD_EXACT_MATCH_DESCRIPTION,
        ),
    ] = None,
    cwe_id: Annotated[
        str | None, Query(alias="cweId", description=CWE_ID_DESCRIPTION)
    ] = None,
    cvss_v2_vector: Annotated[
        str | None,
        Query(alias="cvssV2Metrics", description=CVSS_V2_VECTOR_DESCRIPTION),
    ] = None,
    cvss_v3_vector: Annotated[
        str | None,
        Query(alias="cvssV3Metrics", description=CVSS_V3_VECTOR_DESCRIPTION),
    ] = None,
    cvss_v2_severity: Annotated[
        str | None,
        Query(alias="cvssV2Severity", description=CVSS_V2_SEVERITY_DESCRIPTION),
    ] = None,
    cvss_v3_severity: Annotated[
        str | None,
        Query(alias="cvssV3Severity", description=CVSS_V3_SEVERITY_DESCRIPTION),
    ] = None,
    manager: CVEManagerDependency,
) -> CVEResponse:
    """
    # CVE API

    Provides a similar API to [NVD NIST](https://nvd.nist.gov/developers/vulnerabilities)
    at [https://services.nvd.nist.gov/rest/json/cves/2.0](https://services.nvd.nist.gov/rest/json/cves/2.0).

    # Differences to NVD NIST

    ## Behavior
    * Errors are returned in the body of the HTTP response in JSON format
      instead of in a response header named message.
    * When filtering by [cweId](https://nvd.nist.gov/developers/vulnerabilities#cves-cweId)
      more matching CVEs are found compared to NIST NVD.
    * [keywordExactMatch](https://nvd.nist.gov/developers/vulnerabilities#cves-keywordExactMatch)
      will be just ignored if [keywordSearch](https://nvd.nist.gov/developers/vulnerabilities#cves-keywordSearch)
      is not set, instead of failing with an error.
    * All filters can be combined without raising an error. They are joined
      with an AND clause.
    * It is not required to submit both [lastModStartDate](https://nvd.nist.gov/developers/vulnerabilities#cves-lastModDates)
      and [lastModEndDate](https://nvd.nist.gov/developers/vulnerabilities#cves-lastModDates).
    * It is not required to submit both [pubStartDate](https://nvd.nist.gov/developers/vulnerabilities#cves-pubDates)
      and [pubEndDate](https://nvd.nist.gov/developers/vulnerabilities#cves-pubDates).
    * There is currently no restriction in the date range between [lastModStartDate](https://nvd.nist.gov/developers/vulnerabilities#cves-lastModDates)
      and [lastModEndDate](https://nvd.nist.gov/developers/vulnerabilities#cves-lastModDates).
    * There is currently no restriction in the date range between [pubStartDate](https://nvd.nist.gov/developers/vulnerabilities#cves-pubDates)
      and [pubEndDate](https://nvd.nist.gov/developers/vulnerabilities#cves-pubDates).
    * Lists (for example `cvssMetricV30`) are provided as an empty array if they
      don't contain any element, instead of not being contained in the response
      at all.

    ## Missing
    * Filtering by [cpeName](https://nvd.nist.gov/developers/vulnerabilities#cves-cpeName) -
      Implementing this filter requires to parse the CPE Match criteria and do version comparisons.
      Matching versions is very tricky, inconsistent and error prone. A version may have
      a different meaning depending on the used versioning scheme of the vulnerable software.
      The versioning scheme may change in the lifetime of the software. Until NIST NVD doesn't
      document the version matching algorithms publicly, it is not possible to implement this filter
      with a similar behavior.
    * Filtering by [hasCertAlerts](https://nvd.nist.gov/developers/vulnerabilities#cves-hasCertAlerts) -
      Cert data is not available from the NIST NVD CVE API. NVD must match this data internally for their search.
    * Filtering by [hasCertNotes](https://nvd.nist.gov/developers/vulnerabilities#cves-hasCertNotes) -
      Cert data is not available from the NIST NVD CVE API. NVD must match this data internally for their search.
    * Filtering by [hasKev](https://nvd.nist.gov/developers/vulnerabilities#cves-hasKev) -
      KEV data is not available from the NIST NVD CVE API. NVD must match this data internally for their search.
    * Filtering by [hasOval](https://nvd.nist.gov/developers/vulnerabilities#cves-hasOval) -
      OVAL data is not available from the NIST NVD CVE API. NVD must match this data internally for their search.
    * Filtering by [isVulnerable](https://nvd.nist.gov/developers/vulnerabilities#cves-isVulnerable) -
      Same as cpeName.
    * Filtering by [versionEnd & versionEndType](https://nvd.nist.gov/developers/vulnerabilities#cves-versionEnd) -
      Same as cpeName.
    * Filtering by [versionStart & versionStartType](https://nvd.nist.gov/developers/vulnerabilities#cves-versionStart) -
      Same as cpeName.
    * Filtering by [virtualMatchString](https://nvd.nist.gov/developers/vulnerabilities#cves-virtualMatchString) -
      Same as cpeName.
    """
    no_rejected: bool = no_rejected is not None
    keyword_exact_match: bool = keyword_exact_match is not None
    keywords = (
        keyword_search.split()
        if keyword_search and not keyword_exact_match
        else keyword_search
    )
    filter_args = dict(
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
    cves = await get_cve_items(
        manager, **filter_args, cve_id=cve_id, limit=results_per_page, index=start_index  # type: ignore[arg-type]
    )
    return CVEResponse(
        results_per_page=1 if cve_id else results_per_page,
        total_results=await manager.count(**filter_args, cve_ids=cve_id),
        start_index=start_index,
        timestamp=datetime.now(),
        vulnerabilities=cves,
    )
