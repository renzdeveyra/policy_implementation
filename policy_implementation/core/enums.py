"""
Enums for the policy implementation system.
"""
from enum import Enum, auto

class EntryType(Enum):
    """Types of entries that can be added to the blackboard"""
    ISSUE = auto()
    DIRECTIVE = auto()
    SOLUTION = auto()
    DECISION = auto()
    COMPLIANCE_CONCERN = auto()
    RESOURCE_REQUEST = auto()
    ESCALATION = auto()
    INFORMATION = auto()

class EntryStatus(Enum):
    """Status of blackboard entries"""
    NEW = auto()
    IN_PROGRESS = auto()
    RESOLVED = auto()
    REJECTED = auto()
    NEEDS_CLARIFICATION = auto()
    ESCALATED = auto()

class ExpertRole(Enum):
    """Roles of experts in the system"""
    DDG = auto()  # Deputy Director General
    CIA = auto()  # Chief Internal Auditor
    AA = auto()   # Administrative Assistant

class RuleType(Enum):
    """Types of rules in the system"""
    ISSUE_IDENTIFICATION = auto()
    SOLUTION_GENERATION = auto()
    DECISION_MAKING = auto()
    COMPLIANCE = auto()
    RESOURCE_ALLOCATION = auto()
    ESCALATION = auto()
    INFORMATION_GATHERING = auto()

# Priority levels for different expert roles
PRIORITY_LEVELS = {
    ExpertRole.DDG: 3.0,  # Highest priority
    ExpertRole.CIA: 2.0,
    ExpertRole.AA: 1.0,
    RuleType.ESCALATION: 5.0,  # Highest rule priority
    RuleType.DECISION_MAKING: 4.0,
    RuleType.COMPLIANCE: 3.0,
    RuleType.SOLUTION_GENERATION: 2.0,
    RuleType.ISSUE_IDENTIFICATION: 1.0,
    RuleType.RESOURCE_ALLOCATION: 2.5,
    RuleType.INFORMATION_GATHERING: 1.5,
}
