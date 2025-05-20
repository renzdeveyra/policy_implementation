"""
AdministrativeAssistant expert for the policy implementation system.
"""
import uuid
from typing import List
from policy_implementation.core.enums import ExpertRole, EntryType, EntryStatus, RuleType
from policy_implementation.core.knowledge_source import KnowledgeSource
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.rule import Rule, RuleFactory

class AdministrativeAssistant(KnowledgeSource):
    """Administrative Assistant expert"""
    
    def __init__(self, blackboard: BlackboardInterface, rule_repository=None):
        """
        Initialize the Administrative Assistant expert
        
        Args:
            blackboard: Blackboard to interact with
            rule_repository: Repository for rules
        """
        super().__init__(
            role=ExpertRole.AA,
            name="Administrative Assistant",
            blackboard=blackboard,
            rule_registry=rule_repository
        )
        self.priority = 1.0  # Lower priority
    
    def initialize(self) -> None:
        """Initialize this expert with rules"""
        # Rule 1: Identify procedural issues
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.ISSUE_IDENTIFICATION,
            rule_id="AA_PROCEDURAL_ISSUE",
            description="Identify procedural issues in processes",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and ("process" in entry.content.lower() or "procedure" in entry.content.lower())
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.ISSUE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"information_{uuid.uuid4()}",
                    entry_type=EntryType.INFORMATION,
                    content=f"Procedural analysis for issue: {issue.content}",
                    source=ExpertRole.AA,
                    rule_id="AA_PROCEDURAL_ISSUE",
                    status=EntryStatus.RESOLVED,
                    confidence=0.8,
                    related_entries=[issue.entry_id],
                    metadata={"info_type": "procedural_analysis"}
                )
                for issue in bb.query_entries(entry_type=EntryType.ISSUE, status=EntryStatus.NEW)
                if "process" in issue.content.lower() or "procedure" in issue.content.lower()
            ]
        ))
        
        # Rule 2: Propose administrative solutions
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.SOLUTION_GENERATION,
            rule_id="AA_ADMINISTRATIVE_SOLUTION",
            description="Propose administrative solutions for issues",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.INFORMATION
                and entry.source == ExpertRole.AA
                and entry.status == EntryStatus.RESOLVED
                for entry in bb.query_entries(entry_type=EntryType.INFORMATION)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content="Create standardized templates and checklists to streamline the process",
                    source=ExpertRole.AA,
                    rule_id="AA_ADMINISTRATIVE_SOLUTION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.75,
                    related_entries=[info.entry_id] + info.related_entries,
                    metadata={"action": "procedure_improvement"}
                )
                for info in bb.query_entries(entry_type=EntryType.INFORMATION, source=ExpertRole.AA, status=EntryStatus.RESOLVED)
            ]
        ))
        
        # Rule 3: Identify resource needs
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.RESOURCE_ALLOCATION,
            rule_id="AA_RESOURCE_NEED",
            description="Identify specific resource needs",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and "resource" in entry.content.lower()
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.ISSUE)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"resource_request_{uuid.uuid4()}",
                    entry_type=EntryType.RESOURCE_REQUEST,
                    content=f"Detailed resource request for issue: {issue.content}",
                    source=ExpertRole.AA,
                    rule_id="AA_RESOURCE_NEED",
                    status=EntryStatus.NEW,
                    confidence=0.85,
                    related_entries=[issue.entry_id],
                    metadata={"request_type": "detailed_resource_request"}
                )
                for issue in bb.query_entries(entry_type=EntryType.ISSUE, status=EntryStatus.NEW)
                if "resource" in issue.content.lower()
            ]
        ))
        
        # Rule 4: Process resource requests
        self.add_rule(RuleFactory.create_rule(
            rule_type=RuleType.SOLUTION_GENERATION,
            rule_id="AA_PROCESS_RESOURCE_REQUEST",
            description="Process resource requests",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.RESOURCE_REQUEST
                and entry.status == EntryStatus.NEW
                for entry in bb.query_entries(entry_type=EntryType.RESOURCE_REQUEST)
            ),
            action=lambda bb: [
                BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content="Implement a temporary resource sharing arrangement between departments",
                    source=ExpertRole.AA,
                    rule_id="AA_PROCESS_RESOURCE_REQUEST",
                    status=EntryStatus.RESOLVED,
                    confidence=0.7,
                    related_entries=[request.entry_id] + request.related_entries,
                    metadata={"action": "resource_reallocation"}
                )
                for request in bb.query_entries(entry_type=EntryType.RESOURCE_REQUEST, status=EntryStatus.NEW)
            ]
        ))
