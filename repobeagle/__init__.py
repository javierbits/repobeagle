"""RepoBeagle package.

The scanner lives in cohesive modules; this package re-exports the public surface and
submodules so `import repobeagle` keeps working, and `repobeagle.py` is a shim.

Attribute assignment (`repobeagle.SOMETHING = value`, used by the tests and by
embedders to tweak limits) is forwarded to every module that imported that name,
because a plain package attribute would not affect the scanner's globals.
"""
import sys
import types

from . import core, fetch, report, scanners, service, app, index, release, evidence, cli
from . import rules as rules
from .rules import agent as rules_agent, privacy as rules_privacy
from .rules import RULES, Rule
from .core import *
from .fetch import *
from .report import *
from .scanners import *
from .service import *
from .app import *
from .index import *
from .release import *
from .evidence import *
from .rules.agent import *
from .rules.privacy import *
from .cli import *

# Explicit re-exports: wildcard imports skip underscore helpers, and rule-module
# names are re-exported for tests/tools that reach into them.
from .core import _NO_REMEDIATION_RE
from .core import _REMEDIATION_RE
from .core import _RULE_IDS
from .report import _SARIF_LEVEL
from .scanners import _TOOL_VERSIONS
from .report import _WORKDIRS
from .app import _app_handler
from .app import _app_jwt
from .app import _app_signature_ok
from .release import _artifact_url
from .core import _atomic_write
from .scanners import _cache_root
from .rules.privacy import _card_number_ok
from .scanners import _cargo_direct_names
from .report import _cleanup_workdirs
from .fetch import _copy_bounded
from .fetch import _cosign_arch
from .core import _deadline_left
from .scanners import _dep_norm
from .cli import _disk_version
from .cli import _docker_ok
from .core import _endpoint_noise
from .fetch import _ensure_cosign
from .core import _expiry_days
from .core import _explain_counts
from .core import _explain_rule
from .cli import _feedback_body
from .cli import _feedback_title
from .fetch import _fetch
from .fetch import _fetch_badge_file
from .core import _file_seconds
from .cli import _finding_ref
from .cli import _finding_rule
from .cli import _gate_one
from .cli import _gh_contents
from .scanners import _github_download
from .release import _github_headers
from .core import _gitmodules_entries
from .cli import _head_cache_path
from .core import _host_of
from .core import _iframe_allow_perms
from .core import _in_line_comment
from .rules.privacy import _in_url_authority
from .index import _index_collect
from .index import _index_entries
from .index import _index_page_entries
from .index import _index_paths
from .index import _index_repo_page
from .index import _index_report
from .index import _index_resolve
from .index import _index_scan
from .report import _install_cleanup
from .scanners import _int0
from .core import _is_comment
from .core import _is_own
from .core import _json_file
from .core import _known_host
from .rules.agent import _lev
from .core import _line_of
from .fetch import _local_image_digest
from .rules.privacy import _luhn_ok
from .cli import _mcp_exec
from .cli import _mcp_workdir
from .app import _md
from .release import _normalize_dep
from .scanners import _npm_dep_graph
from .report import _on_signal
from .core import _origin_host
from .core import _pack_fixture_path
from .rules.agent import _package_display_name
from .cli import _parse_ver
from .scanners import _pip_dep_graph
from .rules.privacy import _pkg_is
from .core import _planner_pressure
from .cli import _print_run_report
from .core import _priv_add
from .cli import _pull_image
from .core import _raise_scan_deadline
from .release import _read_json
from .core import _read_version
from .scanners import _registry_cache_path
from .scanners import _registry_fetch
from .release import _release_version
from .cli import _repo_slug
from .cli import _repo_url
from .cli import _retarget_wrapper
from .core import _rule_of
from .scanners import _run
from .fetch import _safe_member_path
from .report import _sbom_cargo
from .report import _sbom_npm
from .report import _sbom_purl
from .report import _sbom_requirements
from .core import _scan_alarm
from .service import _service_handler
from .service import _service_html
from .service import _service_slug
from .core import _strip_yaml_comment
from .rules.privacy import _telem_rx
from .core import _today
from .release import _toml
from .rules.privacy import _tracking_cookie_vendor
from .cli import _trend_count
from .cli import _trend_entry
from .core import _trend_epoch
from .cli import _trend_get
from .cli import _trend_headers
from .cli import _trend_iso
from .cli import _trend_local
from .cli import _trend_published
from .core import _url_host
from .cli import _verify_rescan
from .scanners import _version_sort_key
from .fetch import _web_get
from .core import _yaml_inline
from .core import _yaml_scalar
from .rules.privacy import ADDRESS_INTL_RE
from .rules.privacy import ADDRESS_RE
from .rules.agent import AG_RE
from .rules.privacy import BROWSER_CAPABILITIES
from .rules.agent import BUILD_FETCH_RE
from .rules.privacy import CARD_IIN_RE
from .rules.privacy import CARD_RE
from .rules.privacy import CLIENT_ID_CONTEXT_RE
from .rules.privacy import CLIENT_ID_RE
from .rules.privacy import CMP_LOAD_RE
from .rules.privacy import CONSENT_MODE_RE
from .rules.privacy import CONSENT_STATE_RE
from .rules.privacy import COOKIE_API_RE
from .rules.privacy import COOKIE_FLAG_WORDS
from .rules.privacy import COOKIE_VAR_ARG_RE
from .rules.agent import DIST_RE
from .rules.privacy import DNT_RE
from .rules.agent import DOCKER_FROM_RE
from .rules.privacy import EMAIL_IGNORE
from .rules.privacy import EMAIL_IGNORE_RE
from .rules.privacy import EMAIL_RE
from .rules.privacy import FINGERPRINT_MEANING
from .rules.privacy import FINGERPRINT_RULES
from .rules.privacy import HASHY_RE
from .rules.privacy import IDENTIFY_RE
from .rules.privacy import IMPORT_NET_JS
from .rules.privacy import IMPORT_NET_PY
from .rules.privacy import IOS_DATA_TYPE_NAMES
from .rules.privacy import IOS_DATA_TYPE_RE
from .rules.privacy import IP_LOG_RE
from .rules.privacy import IP_LOG_SINK_RE
from .rules.privacy import LOCKFILE_RE
from .rules.privacy import MACOS_ENTITLEMENTS
from .rules.agent import MAGIC
from .rules.privacy import MAILTO_RE
from .rules.privacy import MASK_KEYS_RE
from .rules.agent import MAX_WORKSPACE_PACKAGES
from .rules.agent import MCP_CODE_RE
from .rules.agent import MCP_NAME_RE
from .rules.agent import MD_EXT
from .rules.agent import MD_RULES
from .rules.privacy import PHONE_CONTEXT_RE
from .rules.privacy import PHONE_LOCAL_RE
from .rules.privacy import PHONE_RE
from .rules.privacy import PII_LOG_RE
from .rules.privacy import PII_OBJECT_RE
from .rules.privacy import PII_ROLE_RE
from .rules.privacy import PII_SKIP_EXT
from .rules.privacy import PII_URL_RE
from .rules.privacy import PII_WORD_RE
from .rules.agent import PIP_EXTRA_INDEX_RE
from .rules.agent import POISON_RE
from .rules.agent import POPULAR
from .rules.privacy import PRIVACY_DOC_NAMES
from .rules.privacy import PRIVACY_DOC_RE
from .rules.privacy import PRIVACY_LINK_RE
from .rules.privacy import PRIVACY_RULE_ORDER
from .rules.privacy import PROTO_REL_RE
from .rules.privacy import PURPOSE_STR_RE
from .rules.privacy import RETENTION_RE
from .rules.registry import RULES
from .rules.privacy import RULESET
from .rules.privacy import SSN_RE
from .rules.agent import STD_BACKENDS
from .rules.privacy import TELEMETRY_MEANING
from .rules.privacy import TELEMETRY_OPTOUT_RE
from .rules.privacy import TELEMETRY_PACKAGES
from .rules.privacy import TELEMETRY_RULES
from .rules.privacy import TEL_LINK_RE
from .rules.privacy import TRACKER_INIT_RE
from .rules.privacy import TRACKING_COOKIE_RE
from .rules.privacy import TRACKING_COOKIE_VENDORS
from .rules.privacy import TRACKING_PARAM_RE
from .rules.privacy import UPLOAD_LIMIT_RE
from .rules.privacy import UPLOAD_SINK_RE
from .rules.privacy import VENDOR_PII_RE
from .rules.privacy import VENDOR_PII_SAFE_RE
from .rules.privacy import ZIP_CONTEXT_RE
from .rules.privacy import ZIP_RE
from .rules.agent import check_agent_text
from .rules.agent import check_build_hooks
from .rules.agent import check_exfil
from .rules.agent import check_install_hooks
from .rules.agent import check_magic
from .rules.agent import check_markdown_hidden
from .rules.agent import check_mcp
from .rules.agent import check_obfuscation_deps
from .rules.agent import check_patterns
from .rules.privacy import check_privacy
from .rules.privacy import check_privacy_signals
from .rules.agent import check_supply_chain
from .rules.privacy import check_telemetry
from .rules.agent import check_tool_poisoning
from .rules.agent import check_unicode
from .rules.agent import check_workflows
from .rules.agent import dep_names
from .rules.privacy import lockfile_packages
from .rules.privacy import privacy_findings
from .rules.agent import run_agent_checks
from .rules.agent import shannon
from .rules.privacy import telemetry_findings
from .rules.agent import trust_findings
from .rules.agent import trust_provenance
from .rules.agent import trust_signals
from .rules.agent import typosquat_of
from .rules.agent import workspace_packages

_SUBMODULES = (core, fetch, report, scanners, service, app, index, release, evidence, cli, rules_agent, rules_privacy)

class _RepobeagleModule(types.ModuleType):
    def __setattr__(self, name, value):
        for module in _SUBMODULES:
            if hasattr(module, name):
                setattr(module, name, value)
        super().__setattr__(name, value)

sys.modules[__name__].__class__ = _RepobeagleModule
