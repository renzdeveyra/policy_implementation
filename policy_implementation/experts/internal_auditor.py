"""
ChiefInternalAuditor expert for the policy implementation system.
"""
import uuid
from typing import List
from policy_implementation.core.enums import ExpertRole, EntryType, EntryStatus, RuleType
from policy_implementation.core.knowledge_source import KnowledgeSource
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.rule import Rule, RuleFactory

class ChiefInternalAuditor(KnowledgeSource):
    """Chief Internal Auditor expert"""
    
    def __init__(self, blackboard: BlackboardInterface, rule_repository=None):
        """
        Initialize the Chief Internal Auditor expert
        
        Args:
            blackboard: Blackboard to interact with
            rule_repository: Repository for rules
        """
        super().__init__(
            role=ExpertRole.CIA,
            name="Chief Internal Auditor",
            blackboard=blackboard,
            rule_registry=rule_repository
        )
        self.priority = 2.0  # Medium priority
    
    def initialize(self) -> None:
        """Initialize this expert with rules"""
        # Rule 1: Identify compliance issues
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.COMPLIANCE,
            rule_id="CIA_COMPLIANCE_CHECK",
            description="Identify compliance issues in directives",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.DIRECTIVE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"compliance_concern_{uuid.uuid4()}",
                    entry_type=EntryType.COMPLIANCE_CONCERN,
                    content=f"Compliance review required for directive: {directive.content}",
                    source=ExpertRole.CIA,
                    rule_id="CIA_COMPLIANCE_CHECK",
                    status=EntryStatus.NEW,
                    confidence=0.9,
                    related_entries=[directive.entry_id],
                    metadata={"concern_type": "compliance_review"}
                )
                for directive in bb.query_entries(entry_type=EntryType.DIRECTIVE, status=EntryStatus.NEW)
            ]
        ))
        
        # Rule 2: Propose compliance solutions
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.SOLUTION_GENERATION,
            rule_id="CIA_COMPLIANCE_SOLUTION",
            description="Propose solutions for compliance concerns",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.COMPLIANCE_CONCERN
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.COMPLIANCE_CONCERN)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content="Conduct formal compliance review before implementation to ensure adherence to regulations",
                    source=ExpertRole.CIA,
                    rule_id="CIA_COMPLIANCE_SOLUTION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.85,
                    related_entries=[concern.entry_id] + concern.related_entries,
                    metadata={"action": "compliance_review"}
                )
                for concern in bb.query_entries(entry_type=EntryType.COMPLIANCE_CONCERN, status=EntryStatus.NEW)
            ]
        ))
        
        # Rule 3: Review approval processes
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.SOLUTION_GENERATION,
            rule_id="CIA_APPROVAL_PROCESS_REVIEW",
            description="Review and improve approval processes",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and "approval" in entry.content.lower()
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.ISSUE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content="Implement a two-tier approval system with clear escalation criteria",
                    source=ExpertRole.CIA,
                    rule_id="CIA_APPROVAL_PROCESS_REVIEW",
                    status=EntryStatus.RESOLVED,
                    confidence=0.8,
                    related_entries=[
                        entry.entry_id for entry in bb.query_entries(entry_type=EntryType.ISSUE)
                        if "approval" in entry.content.lower() and entry.status == EntryStatus.NEW
                    ],
                    metadata={"action": "procedure_improvement"}
                )
            ]
        ))
        
        # Rule 4: Make decisions on compliance concerns
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.DECISION_MAKING,
            rule_id="CIA_COMPLIANCE_DECISION",
            description="Make decisions on compliance concerns",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.COMPLIANCE_CONCERN
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.COMPLIANCE_CONCERN)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"decision_{uuid.uuid4()}",
                    entry_type=EntryType.DECISION,
                    content=f"Require compliance documentation for: {concern.content}",
                    source=ExpertRole.CIA,
                    rule_id="CIA_COMPLIANCE_DECISION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.9,
                    related_entries=[concern.entry_id] + concern.related_entries,
                    metadata={"decision_type": "compliance_requirement"}
                )
                for concern in bb.query_entries(entry_type=EntryType.COMPLIANCE_CONCERN, status=EntryStatus.NEW)
            ]
        ))
