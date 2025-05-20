"""
DeputyDirectorGeneral expert for the policy implementation system.
"""
import uuid
from typing import List
from policy_implementation.core.enums import ExpertRole, EntryType, EntryStatus, RuleType
from policy_implementation.core.knowledge_source import KnowledgeSource
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.rule import Rule, RuleFactory

class DeputyDirectorGeneral(KnowledgeSource):
    """Deputy Director General expert"""
    
    def __init__(self, blackboard: BlackboardInterface, rule_repository=None):
        """
        Initialize the Deputy Director General expert
        
        Args:
            blackboard: Blackboard to interact with
            rule_repository: Repository for rules
        """
        super().__init__(
            role=ExpertRole.DDG,
            name="Deputy Director General",
            blackboard=blackboard,
            rule_registry=rule_repository
        )
        self.priority = 3.0  # Highest priority
    
    def initialize(self) -> None:
        """Initialize this expert with rules"""
        # Rule 1: Identify resource allocation issues
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.ISSUE_IDENTIFICATION,
            rule_id="DDG_RESOURCE_ALLOCATION_ISSUE",
            description="Identify resource allocation issues",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and "resource" in entry.content.lower()
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.ISSUE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content="Reallocate resources from lower priority projects to address the resource shortage",
                    source=ExpertRole.DDG,
                    rule_id="DDG_RESOURCE_ALLOCATION_ISSUE",
                    status=EntryStatus.RESOLVED,
                    confidence=0.9,
                    related_entries=[
                        entry.entry_id for entry in bb.query_entries(entry_type=EntryType.ISSUE)
                        if "resource" in entry.content.lower() and entry.status == EntryStatus.NEW
                    ],
                    metadata={"action": "resource_reallocation"}
                )
            ]
        ))
        
        # Rule 2: Make strategic decisions on directives
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.DECISION_MAKING,
            rule_id="DDG_STRATEGIC_DECISION",
            description="Make strategic decisions on directives",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.DIRECTIVE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"decision_{uuid.uuid4()}",
                    entry_type=EntryType.DECISION,
                    content=f"Approve implementation of directive: {directive.content}",
                    source=ExpertRole.DDG,
                    rule_id="DDG_STRATEGIC_DECISION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.95,
                    related_entries=[directive.entry_id],
                    metadata={"decision_type": "approval"}
                )
                for directive in bb.query_entries(entry_type=EntryType.DIRECTIVE, status=EntryStatus.NEW)
            ]
        ))
        
        # Rule 3: Address approval bottlenecks
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.SOLUTION_GENERATION,
            rule_id="DDG_APPROVAL_BOTTLENECK",
            description="Address approval bottlenecks",
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
                    content="Implement a streamlined approval process with delegation of authority for routine matters",
                    source=ExpertRole.DDG,
                    rule_id="DDG_APPROVAL_BOTTLENECK",
                    status=EntryStatus.RESOLVED,
                    confidence=0.9,
                    related_entries=[
                        entry.entry_id for entry in bb.query_entries(entry_type=EntryType.ISSUE)
                        if "approval" in entry.content.lower() and entry.status == EntryStatus.NEW
                    ],
                    metadata={"action": "streamline_approvals"}
                )
            ]
        ))
        
        # Rule 4: Escalate complex issues
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.ESCALATION,
            rule_id="DDG_ESCALATE_COMPLEX_ISSUES",
            description="Escalate complex issues requiring higher authority",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and entry.status == EntryStatus.NEW
                and ("critical" in entry.content.lower() or "urgent" in entry.content.lower())
                for entry in bb.query_entries(entry_type=EntryType.ISSUE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"escalation_{uuid.uuid4()}",
                    entry_type=EntryType.ESCALATION,
                    content=f"Escalating critical issue to Director General: {issue.content}",
                    source=ExpertRole.DDG,
                    rule_id="DDG_ESCALATE_COMPLEX_ISSUES",
                    status=EntryStatus.ESCALATED,
                    confidence=0.95,
                    related_entries=[issue.entry_id],
                    metadata={"escalation_level": "director_general"}
                )
                for issue in bb.query_entries(entry_type=EntryType.ISSUE, status=EntryStatus.NEW)
                if "critical" in issue.content.lower() or "urgent" in issue.content.lower()
            ]
        ))
