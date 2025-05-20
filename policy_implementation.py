class AdministrativeAssistant(KnowledgeSource):
    """Knowledge source representing the Administrative Assistant"""
    
    def __init__(self):
        super().__init__(ExpertRole.AA, "Administrative Assistant")
        self.setup_rules()
    
    def setup_rules(self):
        """Set up rules based on the AA's expertise"""
        
        # Rule 1: Identify unclear instructions
        self.add_rule(Rule(
            rule_id="AA_UNCLEAR_INSTRUCTIONS",
            rule_type=RuleType.OPERATIONAL,
            description="Identify when instructions for new directives are unclear",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._check_instruction_clarity(bb)
        ))
        
        # Rule 2: Report approval bottlenecks
        self.add_rule(Rule(
            rule_id="AA_APPROVAL_BOTTLENECKS",
            rule_type=RuleType.OPERATIONAL,
            description="Report when approvals are causing workflow bottlenecks",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and any(kw in entry.content.lower() for kw in ["approval", "sign", "authorize"])
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._report_approval_bottlenecks(bb)
        ))
        
        # Rule 3: Flag system and technical issues
        self.add_rule(Rule(
            rule_id="AA_SYSTEM_ISSUES",
            rule_type=RuleType.OPERATIONAL,
            description="Flag system and technical issues affecting workflow",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and any(kw in entry.content.lower() for kw in ["system", "technical", "it", "computer", "network", "internet"])
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._report_system_issues(bb)
        ))
        
        # Rule 4: Suggest procedural improvements
        self.add_rule(Rule(
            rule_id="AA_PROCEDURAL_IMPROVEMENTS",
            rule_type=RuleType.OPERATIONAL,
            description="Suggest improvements to daily operational procedures",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.WORKFLOW_EXCEPTION
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._suggest_procedural_improvements(bb)
        ))
        
        # Rule 5: Request templates and examples
        self.add_rule(Rule(
            rule_id="AA_REQUEST_TEMPLATES",
            rule_type=RuleType.OPERATIONAL,
            description="Request templates and examples for new processes",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and "new" in entry.content.lower()
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._request_templates(bb)
        ))
    
    def _check_instruction_clarity(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Check if instructions for new directives are clear"""
        new_entries = []
        
        # Find new directives
        new_directives = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.DIRECTIVE
            and entry.status == EntryStatus.NEW
        ]
        
        for directive in new_directives:
            # Check if the directive is clear (simple heuristic: longer instructions tend to be clearer)
            is_clear = len(directive.content) > 100 and "step" in directive.content.lower()
            
            if not is_clear:
                # Create an issue for unclear instructions
                issue = BlackboardEntry(
                    entry_id=f"issue_{uuid.uuid4()}",
                    entry_type=EntryType.ISSUE,
                    content=f"Unclear instructions in directive: {directive.content}",
                    source=self.role,
                    rule_id="AA_UNCLEAR_INSTRUCTIONS",
                    status=EntryStatus.NEW,
                    confidence=0.8,
                    related_entries=[directive.entry_id],
                    metadata={"issue_type": "clarity"}
                )
                new_entries.append(issue)
                
                # Create a question asking for clarification
                question = BlackboardEntry(
                    entry_id=f"question_{uuid.uuid4()}",
                    entry_type=EntryType.QUESTION,
                    content=f"Request for clarification: Can you provide step-by-step instructions for implementing this directive?",
                    source=self.role,
                    rule_id="AA_UNCLEAR_INSTRUCTIONS",
                    status=EntryStatus.NEW,
                    confidence=0.9,
                    related_entries=[directive.entry_id, issue.entry_id],
                    metadata={"question_type": "clarification"}
                )
                new_entries.append(question)
            else:
                # Mark the directive as clear and in processing
                blackboard.update_entry(
                    directive.entry_id,
                    status=EntryStatus.PROCESSING
                )
        
        return new_entries
    
    def _report_approval_bottlenecks(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Report when approvals are causing workflow bottlenecks"""
        new_entries = []
        
        # Find approval-related issues
        approval_issues = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE
            and any(kw in entry.content.lower() for kw in ["approval", "sign", "authorize"])
            and entry.status == EntryStatus.NEW
        ]
        
        for issue in approval_issues:
            # Create a workflow exception
            exception = BlackboardEntry(
                entry_id=f"exception_{uuid.uuid4()}",
                entry_type=EntryType.WORKFLOW_EXCEPTION,
                content=f"Approval bottleneck identified: {issue.content}",
                source=self.role,
                rule_id="AA_APPROVAL_BOTTLENECKS",
                status=EntryStatus.NEW,
                confidence=0.9,
                related_entries=[issue.entry_id],
                metadata={"bottleneck_type": "approval"}
            )
            new_entries.append(exception)
            
            # Suggest a solution
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Implement delegated approval authority for routine matters and create a fast-track approval process for urgent items to address: {issue.content}",
                source=self.role,
                rule_id="AA_APPROVAL_BOTTLENECKS",
                status=EntryStatus.RESOLVED,
                confidence=0.7,
                related_entries=[issue.entry_id, exception.entry_id],
                metadata={"action": "delegated_approval"}
            )
            new_entries.append(solution)
            
            # Update the issue status
            blackboard.update_entry(
                issue.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _report_system_issues(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Flag system and technical issues affecting workflow"""
        new_entries = []
        
        # Find system-related issues
        system_issues = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE
            and any(kw in entry.content.lower() for kw in ["system", "technical", "it", "computer", "network", "internet"])
            and entry.status == EntryStatus.NEW
        ]
        
        for issue in system_issues:
            # Create a workflow exception
            exception = BlackboardEntry(
                entry_id=f"exception_{uuid.uuid4()}",
                entry_type=EntryType.WORKFLOW_EXCEPTION,
                content=f"System issue impacting workflow: {issue.content}",
                source=self.role,
                rule_id="AA_SYSTEM_ISSUES",
                status=EntryStatus.NEW,
                confidence=0.95,
                related_entries=[issue.entry_id],
                metadata={"bottleneck_type": "technical"}
            )
            new_entries.append(exception)
            
            # Create a resource request
            request = BlackboardEntry(
                entry_id=f"request_{uuid.uuid4()}",
                entry_type=EntryType.RESOURCE_REQUEST,
                content=f"Request IT support resources to resolve: {issue.content}",
                source=self.role,
                rule_id="AA_SYSTEM_ISSUES",
                status=EntryStatus.NEW,
                confidence=0.9,
                related_entries=[issue.entry_id, exception.entry_id],
                metadata={"resource_type": "it_support"}
            )
            new_entries.append(request)
            
            # Update the issue status
            blackboard.update_entry(
                issue.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _suggest_procedural_improvements(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Suggest improvements to daily operational procedures"""
        new_entries = []
        
        # Find workflow exceptions
        workflow_exceptions = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.WORKFLOW_EXCEPTION
            and entry.status == EntryStatus.NEW
        ]
        
        for exception in workflow_exceptions:
            # Create a solution with procedural improvement
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Operational improvement: Create a formal exception handling process with clear escalation paths for: {exception.content}",
                source=self.role,
                rule_id="AA_PROCEDURAL_IMPROVEMENTS",
                status=EntryStatus.RESOLVED,
                confidence=0.8,
                related_entries=[exception.entry_id],
                metadata={"action": "procedure_improvement"}
            )
            new_entries.append(solution)
            
            # Update the exception status
            blackboard.update_entry(
                exception.entry_id,
                status=EntryStatus.from abc import ABC, abstractmethod
from enum import Enum, auto
import logging
import random
import json
from typing import Dict, List, Any, Optional, Set, Tuple
import time
from datetime import datetime, timedelta
import copy
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("BlackboardExpertSystem")

# ------------------- ENUMS AND CONSTANTS -------------------

class ExpertRole(Enum):
    """Enum for different expert roles in the system"""
    DDG = auto()  # Deputy Director General
    CIA = auto()  # Chief Internal Auditor
    AA = auto()   # Administrative Assistant

class EntryStatus(Enum):
    """Status of entries on the blackboard"""
    NEW = auto()
    PROCESSING = auto()
    RESOLVED = auto()
    NEEDS_CLARIFICATION = auto()
    ESCALATED = auto()
    REJECTED = auto()

class EntryType(Enum):
    """Types of entries that can be placed on the blackboard"""
    FACT = auto()
    ISSUE = auto()
    SOLUTION = auto()
    QUESTION = auto()
    DIRECTIVE = auto()
    RESOURCE_REQUEST = auto()
    COMPLIANCE_CONCERN = auto()
    WORKFLOW_EXCEPTION = auto()
    DECISION = auto()

class RuleType(Enum):
    """Types of rules in the system"""
    STRATEGIC = auto()  # High-level decision rules (DDG)
    COMPLIANCE = auto()  # Compliance and risk rules (CIA)
    OPERATIONAL = auto()  # Day-to-day workflow rules (AA)

# Priority levels for rules and experts
PRIORITY_LEVELS = {
    RuleType.STRATEGIC: 3,
    RuleType.COMPLIANCE: 2,
    RuleType.OPERATIONAL: 1,
    ExpertRole.DDG: 3,
    ExpertRole.CIA: 2,
    ExpertRole.AA: 1
}

# ------------------- CORE DATA STRUCTURES -------------------

class BlackboardEntry:
    """Represents an entry on the blackboard"""
    
    def __init__(self, 
                 entry_id: str,
                 entry_type: EntryType, 
                 content: str, 
                 source: ExpertRole = None,
                 rule_id: str = None,
                 status: EntryStatus = EntryStatus.NEW,
                 confidence: float = 1.0,
                 related_entries: List[str] = None,
                 metadata: Dict[str, Any] = None):
        self.entry_id = entry_id
        self.entry_type = entry_type
        self.content = content
        self.source = source
        self.rule_id = rule_id
        self.status = status
        self.confidence = confidence
        self.created_at = datetime.now()
        self.updated_at = self.created_at
        self.related_entries = related_entries or []
        self.metadata = metadata or {}
    
    def update_status(self, new_status: EntryStatus):
        """Update the status of this entry"""
        self.status = new_status
        self.updated_at = datetime.now()
    
    def add_related_entry(self, entry_id: str):
        """Add a related entry to this entry"""
        if entry_id not in self.related_entries:
            self.related_entries.append(entry_id)
            self.updated_at = datetime.now()
    
    def __str__(self):
        """String representation of the entry"""
        return (f"ID: {self.entry_id} | Type: {self.entry_type.name} | "
                f"Status: {self.status.name} | "
                f"Source: {self.source.name if self.source else 'None'} | "
                f"Content: {self.content[:50]}{'...' if len(self.content) > 50 else ''}")

class Rule:
    """Represents a rule in the expert system"""
    
    def __init__(self, 
                 rule_id: str,
                 rule_type: RuleType,
                 condition: callable,
                 action: callable,
                 description: str,
                 source: ExpertRole,
                 priority: int = None):
        self.rule_id = rule_id
        self.rule_type = rule_type
        self.condition = condition  # Function that evaluates if rule should trigger
        self.action = action  # Function that produces new entries or updates
        self.description = description
        self.source = source
        self.priority = priority or PRIORITY_LEVELS[rule_type]
    
    def evaluate(self, blackboard: 'Blackboard') -> bool:
        """Evaluate if this rule should be triggered"""
        return self.condition(blackboard)
    
    def execute(self, blackboard: 'Blackboard') -> List[BlackboardEntry]:
        """Execute the rule's action"""
        return self.action(blackboard)
    
    def __str__(self):
        return f"Rule {self.rule_id}: {self.description} (Priority: {self.priority}, Source: {self.source.name})"

class Blackboard:
    """Central blackboard that holds all facts and partial solutions"""
    
    def __init__(self):
        self.entries = {}  # Dictionary of entry_id -> BlackboardEntry
        self.history = []  # List of tuples (timestamp, action, details)
    
    def add_entry(self, entry: BlackboardEntry) -> str:
        """Add a new entry to the blackboard"""
        self.entries[entry.entry_id] = entry
        self.log_action("ADD_ENTRY", f"Added entry {entry.entry_id} of type {entry.entry_type.name}")
        return entry.entry_id
    
    def update_entry(self, entry_id: str, **kwargs) -> None:
        """Update an existing entry"""
        if entry_id not in self.entries:
            raise ValueError(f"Entry {entry_id} not found")
        
        entry = self.entries[entry_id]
        updated = False
        
        for key, value in kwargs.items():
            if hasattr(entry, key):
                setattr(entry, key, value)
                updated = True
        
        if updated:
            entry.updated_at = datetime.now()
            self.log_action("UPDATE_ENTRY", f"Updated entry {entry_id}")
    
    def get_entry(self, entry_id: str) -> BlackboardEntry:
        """Get an entry by its ID"""
        return self.entries.get(entry_id)
    
    def get_entries_by_type(self, entry_type: EntryType) -> List[BlackboardEntry]:
        """Get all entries of a specific type"""
        return [entry for entry in self.entries.values() if entry.entry_type == entry_type]
    
    def get_entries_by_status(self, status: EntryStatus) -> List[BlackboardEntry]:
        """Get all entries with a specific status"""
        return [entry for entry in self.entries.values() if entry.status == status]
    
    def get_entries_by_source(self, source: ExpertRole) -> List[BlackboardEntry]:
        """Get all entries from a specific source"""
        return [entry for entry in self.entries.values() if entry.source == source]
    
    def query_entries(self, **kwargs) -> List[BlackboardEntry]:
        """Query entries based on multiple criteria"""
        result = list(self.entries.values())
        
        for key, value in kwargs.items():
            if key == 'entry_type':
                result = [entry for entry in result if entry.entry_type == value]
            elif key == 'status':
                result = [entry for entry in result if entry.status == value]
            elif key == 'source':
                result = [entry for entry in result if entry.source == value]
            elif key == 'older_than':
                threshold = datetime.now() - timedelta(minutes=value)
                result = [entry for entry in result if entry.created_at < threshold]
            elif key == 'newer_than':
                threshold = datetime.now() - timedelta(minutes=value)
                result = [entry for entry in result if entry.created_at > threshold]
        
        return result
    
    def log_action(self, action: str, details: str) -> None:
        """Log an action on the blackboard"""
        self.history.append((datetime.now(), action, details))
        logger.info(f"{action}: {details}")
    
    def print_current_state(self, detailed: bool = False) -> None:
        """Print the current state of the blackboard"""
        print("\n=== BLACKBOARD STATE ===")
        
        # Group entries by type
        entries_by_type = {}
        for entry_type in EntryType:
            entries = self.get_entries_by_type(entry_type)
            if entries:
                entries_by_type[entry_type] = entries
        
        # Print counts
        print(f"Total entries: {len(self.entries)}")
        for entry_type, entries in entries_by_type.items():
            print(f"- {entry_type.name}: {len(entries)}")
        
        if detailed and self.entries:
            print("\nDetailed Entry Information:")
            for entry_id, entry in sorted(self.entries.items()):
                print(f"\n{str(entry)}")
                if entry.related_entries:
                    related = ', '.join(entry.related_entries)
                    print(f"  Related entries: {related}")
        
        print("========================\n")

# ------------------- KNOWLEDGE SOURCE BASE CLASS -------------------

class KnowledgeSource(ABC):
    """Abstract base class for all knowledge sources"""
    
    def __init__(self, role: ExpertRole, name: str):
        self.role = role
        self.name = name
        self.rules = []
        self.priority = PRIORITY_LEVELS[role]
        self.response_time = self._generate_response_time()
        self.last_activated = None
    
    def _generate_response_time(self) -> timedelta:
        """Generate a realistic response time for this expert"""
        # Base response time by role
        base_times = {
            ExpertRole.DDG: 15,  # DDG typically takes longer due to higher responsibilities
            ExpertRole.CIA: 10,  # CIA has medium response time
            ExpertRole.AA: 5     # Administrative assistants typically respond quickest
        }
        
        # Add some randomness (±30%)
        base = base_times[self.role]
        variation = random.uniform(0.7, 1.3)
        minutes = base * variation
        
        return timedelta(minutes=minutes)
    
    def is_available(self) -> bool:
        """Check if this knowledge source is available to respond"""
        if self.last_activated is None:
            return True
        
        time_since_last = datetime.now() - self.last_activated
        return time_since_last >= self.response_time
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to this knowledge source"""
        self.rules.append(rule)
    
    def get_applicable_rules(self, blackboard: Blackboard) -> List[Rule]:
        """Get all rules that can be applied to the current blackboard state"""
        return [rule for rule in self.rules if rule.evaluate(blackboard)]
    
    def activate(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Activate this knowledge source to contribute to the blackboard"""
        self.last_activated = datetime.now()
        applicable_rules = self.get_applicable_rules(blackboard)
        
        if not applicable_rules:
            logger.info(f"No applicable rules found for {self.name}")
            return []
        
        # Sort rules by priority (highest first)
        applicable_rules.sort(key=lambda r: r.priority, reverse=True)
        highest_priority_rule = applicable_rules[0]
        
        logger.info(f"Activating {self.name} with rule: {highest_priority_rule.description}")
        
        # Execute the highest priority rule
        return highest_priority_rule.execute(blackboard)
    
    @abstractmethod
    def setup_rules(self) -> None:
        """Set up the rules for this knowledge source"""
        pass

# ------------------- CONTROL SHELL -------------------

class ControlShell:
    """Manages the activation of knowledge sources and conflict resolution"""
    
    def __init__(self, blackboard: Blackboard, knowledge_sources: List[KnowledgeSource]):
        self.blackboard = blackboard
        self.knowledge_sources = knowledge_sources
        self.reasoning_cycles = 0
        self.max_reasoning_cycles = 20
        self.unaddressed_entries = set()  # Entries that haven't been addressed
        self.consecutive_cycles_without_changes = 0
        self.max_cycles_without_changes = 3
    
    def run_reasoning_cycle(self) -> bool:
        """Run a single reasoning cycle
        
        Returns:
            bool: True if should continue, False if should stop
        """
        self.reasoning_cycles += 1
        logger.info(f"=== Starting reasoning cycle {self.reasoning_cycles} ===")
        
        # Track which entries have no changes this cycle
        current_entries = set(self.blackboard.entries.keys())
        new_entries_this_cycle = set()
        updated_entries_this_cycle = set()
        
        # Get available knowledge sources
        available_ks = [ks for ks in self.knowledge_sources if ks.is_available()]
        
        if not available_ks:
            logger.info("No knowledge sources available this cycle")
            self.consecutive_cycles_without_changes += 1
            return True
        
        # Sort by priority
        available_ks.sort(key=lambda ks: ks.priority, reverse=True)
        
        # Track initial blackboard state
        initial_state = copy.deepcopy(self.blackboard.entries)
        
        # Activate each knowledge source
        contributions = []
        for ks in available_ks:
            new_entries = ks.activate(self.blackboard)
            if new_entries:
                logger.info(f"{ks.name} contributed {len(new_entries)} entries")
                contributions.extend((ks, entry) for entry in new_entries)
                new_entries_this_cycle.update(entry.entry_id for entry in new_entries)
        
        # Process all contributions
        for ks, entry in contributions:
            # First check for conflicts
            conflicts = self._detect_conflicts(entry)
            
            if conflicts:
                # Resolve conflicts
                resolution = self._resolve_conflicts(entry, conflicts)
                if resolution != entry:
                    # Replace the entry with the resolution
                    self.blackboard.update_entry(entry.entry_id, 
                                              status=resolution.status,
                                              content=resolution.content,
                                              confidence=resolution.confidence)
                    updated_entries_this_cycle.add(entry.entry_id)
            
            # Add the entry (or resolved version) to the blackboard
            self.blackboard.add_entry(entry)
        
        # Check for entries that have been updated
        for entry_id, entry in self.blackboard.entries.items():
            if entry_id in initial_state:
                old_entry = initial_state[entry_id]
                if (entry.status != old_entry.status or 
                    entry.content != old_entry.content or
                    entry.confidence != old_entry.confidence):
                    updated_entries_this_cycle.add(entry_id)
        
        # Update consecutive cycles without changes
        if new_entries_this_cycle or updated_entries_this_cycle:
            self.consecutive_cycles_without_changes = 0
        else:
            self.consecutive_cycles_without_changes += 1
        
        # Add unaddressed entries from this cycle
        unaddressed = current_entries - updated_entries_this_cycle - new_entries_this_cycle
        self.unaddressed_entries.update(unaddressed)
        
        # Check for entries that were addressed in this cycle
        addressed = self.unaddressed_entries.intersection(updated_entries_this_cycle)
        self.unaddressed_entries -= addressed
        
        # Print the current state of the blackboard
        self.blackboard.print_current_state(detailed=True)
        
        # Check termination conditions
        return self._should_continue()
    
    def _detect_conflicts(self, new_entry: BlackboardEntry) -> List[BlackboardEntry]:
        """Detect conflicts between a new entry and existing entries
        
        Args:
            new_entry: The new entry to check for conflicts
            
        Returns:
            List of conflicting entries
        """
        conflicts = []
        
        # Only certain entry types can conflict
        if new_entry.entry_type in [EntryType.SOLUTION, EntryType.DECISION]:
            # Check for entries of the same type with different solutions
            similar_entries = self.blackboard.get_entries_by_type(new_entry.entry_type)
            
            for entry in similar_entries:
                # Simple conflict detection - if they relate to the same issues but have different content
                if (set(entry.related_entries) & set(new_entry.related_entries) and
                    entry.content != new_entry.content):
                    conflicts.append(entry)
        
        return conflicts
    
    def _resolve_conflicts(self, new_entry: BlackboardEntry, conflicts: List[BlackboardEntry]) -> BlackboardEntry:
        """Resolve conflicts between entries
        
        Args:
            new_entry: The new entry
            conflicts: List of conflicting entries
            
        Returns:
            The resolved entry
        """
        if not conflicts:
            return new_entry
        
        logger.info(f"Resolving conflicts for entry {new_entry.entry_id} with {len(conflicts)} conflicts")
        
        # Strategy 1: Role-based priority
        if new_entry.source:
            new_priority = PRIORITY_LEVELS[new_entry.source]
            highest_conflict_priority = max(
                PRIORITY_LEVELS.get(conflict.source, 0) for conflict in conflicts
            )
            
            if new_priority > highest_conflict_priority:
                # New entry has higher priority
                for conflict in conflicts:
                    self.blackboard.update_entry(
                        conflict.entry_id, 
                        status=EntryStatus.REJECTED,
                        metadata={**conflict.metadata, "rejected_by": new_entry.entry_id}
                    )
                return new_entry
            elif new_priority < highest_conflict_priority:
                # Existing entry has higher priority
                new_entry.status = EntryStatus.REJECTED
                new_entry.metadata["rejected_reason"] = "Lower priority than existing entries"
                return new_entry
        
        # Strategy 2: Use confidence scores if priorities are equal
        new_confidence = new_entry.confidence
        conflict_confidences = [conflict.confidence for conflict in conflicts]
        
        if new_confidence > max(conflict_confidences):
            # New entry has higher confidence
            for conflict in conflicts:
                self.blackboard.update_entry(
                    conflict.entry_id, 
                    status=EntryStatus.REJECTED,
                    metadata={**conflict.metadata, "rejected_by": new_entry.entry_id}
                )
            return new_entry
        
        # Strategy 3: If still tied, escalate for human intervention
        new_entry.status = EntryStatus.NEEDS_CLARIFICATION
        new_entry.metadata["conflict_with"] = [conflict.entry_id for conflict in conflicts]
        
        return new_entry
    
    def _should_continue(self) -> bool:
        """Determine if the reasoning process should continue"""
        # Stop if maximum cycles reached
        if self.reasoning_cycles >= self.max_reasoning_cycles:
            logger.info(f"Reached maximum reasoning cycles ({self.max_reasoning_cycles})")
            return False
        
        # Stop if no changes for several consecutive cycles
        if self.consecutive_cycles_without_changes >= self.max_cycles_without_changes:
            logger.info(f"No changes for {self.consecutive_cycles_without_changes} consecutive cycles")
            return False
        
        # Stop if all entries are resolved or rejected
        open_entries = [
            entry for entry in self.blackboard.entries.values()
            if entry.status not in [EntryStatus.RESOLVED, EntryStatus.REJECTED]
        ]
        if not open_entries:
            logger.info("All entries are resolved or rejected")
            return False
        
        return True
    
    def run_to_completion(self) -> None:
        """Run the reasoning process until completion"""
        while self.run_reasoning_cycle():
            time.sleep(0.5)  # Small delay to make output readable
        
        logger.info("=== Reasoning process complete ===")
        self._generate_final_report()
    
    def _generate_final_report(self) -> None:
        """Generate a final report of the reasoning process"""
        print("\n" + "=" * 60)
        print("FINAL REPORT - POLICY IMPLEMENTATION BOTTLENECK RESOLUTION")
        print("=" * 60)
        
        # Summary statistics
        print("\n1. SUMMARY STATISTICS")
        print("-" * 30)
        print(f"Total reasoning cycles: {self.reasoning_cycles}")
        print(f"Total entries processed: {len(self.blackboard.entries)}")
        
        # Count entries by type
        type_counts = {}
        for entry_type in EntryType:
            count = len(self.blackboard.get_entries_by_type(entry_type))
            if count > 0:
                type_counts[entry_type] = count
        
        print("\nEntries by type:")
        for entry_type, count in type_counts.items():
            print(f"- {entry_type.name}: {count}")
        
        # Count entries by status
        status_counts = {}
        for status in EntryStatus:
            count = len(self.blackboard.get_entries_by_status(status))
            if count > 0:
                status_counts[status] = count
        
        print("\nEntries by status:")
        for status, count in status_counts.items():
            print(f"- {status.name}: {count}")
        
        # Count entries by source
        source_counts = {}
        for source in ExpertRole:
            count = len(self.blackboard.get_entries_by_source(source))
            if count > 0:
                source_counts[source] = count
        
        print("\nContributions by expert:")
        for source, count in source_counts.items():
            print(f"- {source.name}: {count}")
        
        # Solutions and decisions
        print("\n2. RECOMMENDED ACTIONS")
        print("-" * 30)
        
        solutions = self.blackboard.get_entries_by_type(EntryType.SOLUTION)
        decisions = self.blackboard.get_entries_by_type(EntryType.DECISION)
        
        # Filter for resolved solutions and decisions
        resolved_solutions = [s for s in solutions if s.status == EntryStatus.RESOLVED]
        resolved_decisions = [d for d in decisions if d.status == EntryStatus.RESOLVED]
        
        if resolved_solutions:
            print("\nRecommended Solutions:")
            for i, solution in enumerate(resolved_solutions, 1):
                print(f"\n{i}. {solution.content}")
                if solution.source:
                    print(f"   Proposed by: {solution.source.name}")
                if solution.related_entries:
                    related_issues = []
                    for rel_id in solution.related_entries:
                        rel_entry = self.blackboard.get_entry(rel_id)
                        if rel_entry and rel_entry.entry_type == EntryType.ISSUE:
                            related_issues.append(rel_entry.content)
                    
                    if related_issues:
                        print("   Addresses issues:")
                        for issue in related_issues:
                            print(f"   - {issue}")
        
        if resolved_decisions:
            print("\nDecisions:")
            for i, decision in enumerate(resolved_decisions, 1):
                print(f"\n{i}. {decision.content}")
                if decision.source:
                    print(f"   Made by: {decision.source.name}")
        
        # Unresolved issues
        unresolved_issues = [
            entry for entry in self.blackboard.get_entries_by_type(EntryType.ISSUE)
            if entry.status not in [EntryStatus.RESOLVED, EntryStatus.REJECTED]
        ]
        
        if unresolved_issues:
            print("\n3. UNRESOLVED ISSUES")
            print("-" * 30)
            for i, issue in enumerate(unresolved_issues, 1):
                print(f"\n{i}. {issue.content}")
                print(f"   Status: {issue.status.name}")
        
        # Conflicts detected
        conflict_entries = [
            entry for entry in self.blackboard.entries.values()
            if entry.status == EntryStatus.NEEDS_CLARIFICATION
        ]
        
        if conflict_entries:
            print("\n4. CONFLICTS REQUIRING HUMAN INTERVENTION")
            print("-" * 30)
            for i, entry in enumerate(conflict_entries, 1):
                print(f"\n{i}. {entry.content}")
                if "conflict_with" in entry.metadata:
                    conflict_ids = entry.metadata["conflict_with"]
                    conflicts = [self.blackboard.get_entry(cid) for cid in conflict_ids]
                    print("   Conflicts with:")
                    for conflict in conflicts:
                        if conflict:
                            print(f"   - {conflict.content}")
                            if conflict.source:
                                print(f"     (From: {conflict.source.name})")
        
        print("\n" + "=" * 60)

# ------------------- SPECIFIC KNOWLEDGE SOURCES -------------------

class DeputyDirectorGeneral(KnowledgeSource):
    """Knowledge source representing the Deputy Director General"""
    
    def __init__(self):
        super().__init__(ExpertRole.DDG, "Deputy Director General")
        self.setup_rules()
    
    def setup_rules(self):
        """Set up rules based on the DDG's expertise"""
        
        # Rule 1: Prioritize issues based on impact on public service delivery
        self.add_rule(Rule(
            rule_id="DDG_PRIORITIZE_SERVICE_IMPACT",
            rule_type=RuleType.STRATEGIC,
            description="Prioritize issues based on impact on public service delivery",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE 
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._prioritize_service_impact(bb)
        ))
        
        # Rule 2: Address resource allocation issues
        self.add_rule(Rule(
            rule_id="DDG_RESOURCE_ALLOCATION",
            rule_type=RuleType.STRATEGIC,
            description="Address resource allocation issues",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.RESOURCE_REQUEST
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._handle_resource_requests(bb)
        ))
        
        # Rule 3: Create interdepartmental coordination for policy clarification
        self.add_rule(Rule(
            rule_id="DDG_COORDINATION_MEETINGS",
            rule_type=RuleType.STRATEGIC,
            description="Initiate interdepartmental meetings for policy clarification",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and "interpretation" in entry.content.lower()
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._setup_coordination_meetings(bb)
        ))
        
        # Rule 4: Escalate critical compliance issues
        self.add_rule(Rule(
            rule_id="DDG_ESCALATE_COMPLIANCE",
            rule_type=RuleType.STRATEGIC,
            description="Escalate critical compliance issues to higher management",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.COMPLIANCE_CONCERN
                and entry.status == EntryStatus.NEW
                and any(kw in entry.content.lower() for kw in ["critical", "urgent", "severe", "risk"])
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._escalate_compliance_issues(bb)
        ))
        
        # Rule 5: Address bureaucratic inertia
        self.add_rule(Rule(
            rule_id="DDG_ADDRESS_INERTIA",
            rule_type=RuleType.STRATEGIC,
            description="Address bureaucratic inertia and resistance to change",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.ISSUE
                and any(kw in entry.content.lower() for kw in ["delay", "resistance", "inertia", "slow"])
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._address_bureaucratic_inertia(bb)
        ))
    
    def _prioritize_service_impact(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Prioritize issues based on impact on public service delivery"""
        new_entries = []
        
        # Find all NEW issues
        issues = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE and entry.status == EntryStatus.NEW
        ]
        
        for issue in issues:
            # Analyze impact on service delivery
            service_impact = "high" if any(kw in issue.content.lower() 
                                         for kw in ["service", "public", "delivery", "citizen"]) else "low"
            
            if service_impact == "high":
                # Create a decision to prioritize this issue
                decision = BlackboardEntry(
                    entry_id=f"decision_{uuid.uuid4()}",
                    entry_type=EntryType.DECISION,
                    content=f"Prioritize addressing this issue due to its high impact on public service delivery: {issue.content}",
                    source=self.role,
                    rule_id="DDG_PRIORITIZE_SERVICE_IMPACT",
                    status=EntryStatus.RESOLVED,
                    confidence=0.9,
                    related_entries=[issue.entry_id],
                    metadata={"priority": "high", "impact_area": "service_delivery"}
                )
                new_entries.append(decision)
                
                # Update the issue status
                blackboard.update_entry(
                    issue.entry_id,
                    status=EntryStatus.PROCESSING,
                    metadata={**issue.metadata, "priority": "high"}
                )
        
        return new_entries
    
    def _handle_resource_requests(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Address resource allocation issues"""
        new_entries = []
        
        # Find all NEW resource requests
        requests = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.RESOURCE_REQUEST and entry.status == EntryStatus.NEW
        ]
        
        for request in requests:
            # Check if resources are available
            resource_shortage = "shortage" in request.content.lower() or "lack" in request.content.lower()
            
            if resource_shortage:
                # Create a solution for resource reallocation
                solution = BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content=f"Reallocate resources from lower priority projects to address: {request.content}",
                    source=self.role,
                    rule_id="DDG_RESOURCE_ALLOCATION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.85,
                    related_entries=[request.entry_id],
                    metadata={"action": "resource_reallocation"}
                )
                new_entries.append(solution)
            else:
                # Create a directive to approve resource request
                directive = BlackboardEntry(
                    entry_id=f"directive_{uuid.uuid4()}",
                    entry_type=EntryType.DIRECTIVE,
                    content=f"Approve and process resource request: {request.content}",
                    source=self.role,
                    rule_id="DDG_RESOURCE_ALLOCATION",
                    status=EntryStatus.RESOLVED,
                    confidence=0.9,
                    related_entries=[request.entry_id],
                    metadata={"action": "approve_request"}
                )
                new_entries.append(directive)
            
            # Update the request status
            blackboard.update_entry(
                request.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _setup_coordination_meetings(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Initiate interdepartmental meetings for policy clarification"""
        new_entries = []
        
        # Find issues related to policy interpretation
        interpretation_issues = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE 
            and "interpretation" in entry.content.lower()
            and entry.status == EntryStatus.NEW
        ]
        
        for issue in interpretation_issues:
            # Create a solution for interdepartmental meeting
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Initiate direct interdepartmental meeting to clarify policy interpretation for: {issue.content}",
                source=self.role,
                rule_id="DDG_COORDINATION_MEETINGS",
                status=EntryStatus.RESOLVED,
                confidence=0.9,
                related_entries=[issue.entry_id],
                metadata={"action": "interdepartmental_meeting"}
            )
            new_entries.append(solution)
            
            # Update the issue status
            blackboard.update_entry(
                issue.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _escalate_compliance_issues(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Escalate critical compliance issues to higher management"""
        new_entries = []
        
        # Find critical compliance concerns
        critical_concerns = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.COMPLIANCE_CONCERN
            and entry.status == EntryStatus.NEW
            and any(kw in entry.content.lower() for kw in ["critical", "urgent", "severe", "risk"])
        ]
        
        for concern in critical_concerns:
            # Create a decision to escalate
            decision = BlackboardEntry(
                entry_id=f"decision_{uuid.uuid4()}",
                entry_type=EntryType.DECISION,
                content=f"Escalate to higher management for immediate attention: {concern.content}",
                source=self.role,
                rule_id="DDG_ESCALATE_COMPLIANCE",
                status=EntryStatus.RESOLVED,
                confidence=0.95,
                related_entries=[concern.entry_id],
                metadata={"action": "escalate_to_management"}
            )
            new_entries.append(decision)
            
            # Update the concern status
            blackboard.update_entry(
                concern.entry_id,
                status=EntryStatus.ESCALATED
            )
        
        return new_entries
    
    def _address_bureaucratic_inertia(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Address bureaucratic inertia and resistance to change"""
        new_entries = []
        
        # Find issues related to bureaucratic inertia
        inertia_issues = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE
            and any(kw in entry.content.lower() for kw in ["delay", "resistance", "inertia", "slow"])
            and entry.status == EntryStatus.NEW
        ]
        
        for issue in inertia_issues:
            # Create a solution
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Implement a phased approach with clear deadlines and accountabilities to overcome resistance: {issue.content}",
                source=self.role,
                rule_id="DDG_ADDRESS_INERTIA",
                status=EntryStatus.RESOLVED,
                confidence=0.8,
                related_entries=[issue.entry_id],
                metadata={"action": "phased_implementation", "focus": "accountability"}
            )
            new_entries.append(solution)
            
            # Update the issue status
            blackboard.update_entry(
                issue.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries