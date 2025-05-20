import uuid
import random
import logging
import copy
from enum import Enum, auto
from datetime import datetime, timedelta
from typing import List, Dict, Any, Callable, Tuple, Set, Optional
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
    TASK = auto()  # Added TASK entry type

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
    """Abstract base class for knowledge sources"""
    
    def __init__(self, role: ExpertRole, name: str):
        self.role = role
        self.name = name
        self.rules = []
        self.priority = 1.0  # Default priority
        self.last_activated = None
        self.cooldown_period = timedelta(seconds=0)  # Changed from 5 to 0 to allow immediate reactivation
    
    def add_rule(self, rule: Rule) -> None:
        """Add a rule to this knowledge source"""
        self.rules.append(rule)
    
    def is_available(self) -> bool:
        """Check if this knowledge source is available to contribute"""
        if self.last_activated is None:
            return True
        
        time_since_last_activation = datetime.now() - self.last_activated
        return time_since_last_activation >= self.cooldown_period
    
    def get_applicable_rules(self, blackboard: Blackboard) -> List[Rule]:
        """Get all rules that are applicable to the current blackboard state"""
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
    """Control shell that manages the reasoning process"""
    
    def __init__(self, blackboard: Blackboard, knowledge_sources: List[KnowledgeSource]):
        self.blackboard = blackboard
        self.knowledge_sources = knowledge_sources
        self.reasoning_cycles = 0
        self.max_reasoning_cycles = 10  # Increased from 5 to 10
        self.consecutive_cycles_without_changes = 0
        self.max_cycles_without_changes = 3
        self.unaddressed_entries = set()
    
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
            
            # Force all knowledge sources to be available again
            for ks in self.knowledge_sources:
                ks.last_activated = None
                
            self.consecutive_cycles_without_changes += 1
            return self._should_continue()
        
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
        
        # Check if there were any changes this cycle
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
        
        # Rule 1: Prioritize service impact
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
        
        # Rule 2: Resource allocation
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
        
        # Rule 3: Interdepartmental coordination
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
        
        # Rule 4: Escalate compliance issues
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
        
        # Rule 6: Handle workflow exceptions
        self.add_rule(Rule(
            rule_id="DDG_HANDLE_EXCEPTIONS",
            rule_type=RuleType.STRATEGIC,
            description="Handle workflow exceptions that require strategic decisions",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.WORKFLOW_EXCEPTION
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._handle_workflow_exceptions(bb)
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
    
    def _handle_workflow_exceptions(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Handle workflow exceptions that require strategic decisions"""
        new_entries = []
        
        # Find workflow exceptions
        exceptions = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.WORKFLOW_EXCEPTION
            and entry.status == EntryStatus.NEW
        ]
        
        for exception in exceptions:
            # Create a strategic decision
            decision = BlackboardEntry(
                entry_id=f"decision_{uuid.uuid4()}",
                entry_type=EntryType.DECISION,
                content=f"Strategic decision to address workflow exception: {exception.content}",
                source=self.role,
                rule_id="DDG_HANDLE_EXCEPTIONS",
                status=EntryStatus.RESOLVED,
                confidence=0.9,
                related_entries=[exception.entry_id],
                metadata={"decision_type": "strategic"}
            )
            new_entries.append(decision)
            
            # Update the exception status
            blackboard.update_entry(
                exception.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries

class AdministrativeAssistant(KnowledgeSource):
    """Knowledge source representing the Administrative Assistant"""
    
    def __init__(self):
        super().__init__(ExpertRole.AA, "Administrative Assistant")
        self.setup_rules()
    
    def setup_rules(self):
        """Set up rules based on the AA's expertise"""
        
        # Rule 1: Report when approvals are causing workflow bottlenecks
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
        
        # Rule 2: Handle routine administrative tasks
        self.add_rule(Rule(
            rule_id="AA_ROUTINE_TASKS",
            rule_type=RuleType.OPERATIONAL,
            description="Address routine administrative tasks",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.TASK
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._handle_routine_tasks(bb)
        ))
        
        # Rule 3: Suggest improvements to daily operational procedures
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
        
        # Rule 4: Request templates and examples for new processes
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
        
        # Rule 5: Document compliance requirements
        self.add_rule(Rule(
            rule_id="AA_DOCUMENT_COMPLIANCE",
            rule_type=RuleType.OPERATIONAL,
            description="Document compliance requirements for new policies",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.COMPLIANCE_CONCERN
                and entry.status == EntryStatus.NEW
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._document_compliance_requirements(bb)
        ))
    
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
            # Create a solution with streamlined approval process
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Streamline approval process by implementing: 1) Delegation of authority for routine approvals, 2) Digital approval system, 3) Parallel processing where possible for: {issue.content}",
                source=self.role,
                rule_id="AA_APPROVAL_BOTTLENECKS",
                status=EntryStatus.RESOLVED,
                confidence=0.85,
                related_entries=[issue.entry_id],
                metadata={"action": "streamline_approvals"}
            )
            new_entries.append(solution)
            
            # Create a workflow exception entry
            exception = BlackboardEntry(
                entry_id=f"exception_{uuid.uuid4()}",
                entry_type=EntryType.WORKFLOW_EXCEPTION,
                content=f"Current approval process creates bottlenecks and delays in: {issue.content}",
                source=self.role,
                rule_id="AA_APPROVAL_BOTTLENECKS",
                status=EntryStatus.NEW,
                confidence=0.9,
                related_entries=[issue.entry_id],
                metadata={"exception_type": "approval_bottleneck"}
            )
            new_entries.append(exception)
            
            # Update the issue status
            blackboard.update_entry(
                issue.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _document_compliance_requirements(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Document compliance requirements for new policies"""
        new_entries = []
        
        # Find compliance concerns
        compliance_concerns = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.COMPLIANCE_CONCERN
            and entry.status == EntryStatus.NEW
        ]
        
        for concern in compliance_concerns:
            # Create a documentation task
            task = BlackboardEntry(
                entry_id=f"task_{uuid.uuid4()}",
                entry_type=EntryType.TASK,
                content=f"Document compliance requirements and create checklist for: {concern.content}",
                source=self.role,
                rule_id="AA_DOCUMENT_COMPLIANCE",
                status=EntryStatus.NEW,
                confidence=0.9,
                related_entries=[concern.entry_id],
                metadata={"task_type": "documentation"}
            )
            new_entries.append(task)
            
            # Update the concern status
            blackboard.update_entry(
                concern.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries
    
    def _handle_routine_tasks(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Address routine administrative tasks"""
        new_entries = []
        
        # Find all NEW tasks
        tasks = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.TASK and entry.status == EntryStatus.NEW
        ]
        
        for task in tasks:
            # Create a solution for the task
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Routine task handled: {task.content}",
                source=self.role,
                rule_id="AA_ROUTINE_TASKS",
                status=EntryStatus.RESOLVED,
                confidence=0.95,
                related_entries=[task.entry_id],
                metadata={"action": "task_completion"}
            )
            new_entries.append(solution)
            
            # Update the task status
            blackboard.update_entry(
                task.entry_id,
                status=EntryStatus.RESOLVED
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
                status=EntryStatus.PROCESSING
            )
            
            # Create a directive for implementation
            directive = BlackboardEntry(
                entry_id=f"directive_{uuid.uuid4()}",
                entry_type=EntryType.DIRECTIVE,
                content=f"Implement standardized procedure for handling: {exception.content}",
                source=self.role,
                rule_id="AA_PROCEDURAL_IMPROVEMENTS",
                status=EntryStatus.NEW,
                confidence=0.75,
                related_entries=[exception.entry_id, solution.entry_id],
                metadata={"action_type": "standardization"}
            )
            new_entries.append(directive)
        
        return new_entries
    
    def _request_templates(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Request templates and examples for new processes"""
        new_entries = []
        
        # Find new directives that mention new processes
        new_process_directives = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.DIRECTIVE
            and "new" in entry.content.lower()
            and entry.status == EntryStatus.NEW
        ]
        
        for directive in new_process_directives:
            # Create a resource request for templates
            request = BlackboardEntry(
                entry_id=f"request_{uuid.uuid4()}",
                entry_type=EntryType.RESOURCE_REQUEST,
                content=f"Request for templates and examples to implement: {directive.content}",
                source=self.role,
                rule_id="AA_REQUEST_TEMPLATES",
                status=EntryStatus.NEW,
                confidence=0.85,
                related_entries=[directive.entry_id],
                metadata={"request_type": "templates"}
            )
            new_entries.append(request)
            
            # Update the directive status
            blackboard.update_entry(
                directive.entry_id,
                status=EntryStatus.PROCESSING
            )
        
        return new_entries

class ChiefInternalAuditor(KnowledgeSource):
    """Knowledge source representing the Chief Internal Auditor"""
    
    def __init__(self):
        super().__init__(ExpertRole.CIA, "Chief Internal Auditor")
        self.setup_rules()
    
    def setup_rules(self):
        """Set up rules based on the CIA's expertise"""
        
        # Rule 1: Identify compliance risks
        self.add_rule(Rule(
            rule_id="CIA_COMPLIANCE_RISKS",
            rule_type=RuleType.COMPLIANCE,  # Changed from REGULATORY to COMPLIANCE
            description="Identify compliance risks in new directives",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and entry.status in [EntryStatus.NEW, EntryStatus.PROCESSING]
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._identify_compliance_risks(bb)
        ))
        
        # Rule 2: Evaluate control effectiveness
        self.add_rule(Rule(
            rule_id="CIA_CONTROL_EFFECTIVENESS",
            rule_type=RuleType.COMPLIANCE,  # Changed from REGULATORY to COMPLIANCE
            description="Evaluate effectiveness of existing controls",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.SOLUTION
                and entry.status == EntryStatus.RESOLVED
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._evaluate_control_effectiveness(bb)
        ))
        
        # Rule 3: Recommend audit procedures
        self.add_rule(Rule(
            rule_id="CIA_AUDIT_PROCEDURES",
            rule_type=RuleType.COMPLIANCE,  # Changed from REGULATORY to COMPLIANCE
            description="Recommend audit procedures for new processes",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.DIRECTIVE
                and "new" in entry.content.lower()
                and entry.status in [EntryStatus.NEW, EntryStatus.PROCESSING]
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._recommend_audit_procedures(bb)
        ))
        
        # Rule 4: Flag potential fraud risks
        self.add_rule(Rule(
            rule_id="CIA_FRAUD_RISKS",
            rule_type=RuleType.COMPLIANCE,  # Changed from REGULATORY to COMPLIANCE
            description="Flag potential fraud risks in processes",
            source=self.role,
            condition=lambda bb: any(
                (entry.entry_type == EntryType.SOLUTION or entry.entry_type == EntryType.DIRECTIVE)
                and any(kw in entry.content.lower() for kw in ["approval", "payment", "finance", "budget", "resource"])
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._flag_fraud_risks(bb)
        ))
        
        # Rule 5: Ensure segregation of duties
        self.add_rule(Rule(
            rule_id="CIA_SEGREGATION_DUTIES",
            rule_type=RuleType.COMPLIANCE,  # Changed from REGULATORY to COMPLIANCE
            description="Ensure proper segregation of duties in processes",
            source=self.role,
            condition=lambda bb: any(
                entry.entry_type == EntryType.SOLUTION
                and any(kw in entry.content.lower() for kw in ["process", "procedure", "workflow", "approval"])
                and entry.status == EntryStatus.RESOLVED
                for entry in bb.entries.values()
            ),
            action=lambda bb: self._ensure_segregation_duties(bb)
        ))
    
    def _identify_compliance_risks(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Identify compliance risks in new directives"""
        new_entries = []
        
        # Find relevant directives
        directives = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.DIRECTIVE
            and entry.status in [EntryStatus.NEW, EntryStatus.PROCESSING]
        ]
        
        for directive in directives:
            # Check for compliance risk keywords
            compliance_risk = any(kw in directive.content.lower() 
                                for kw in ["regulation", "compliance", "legal", "requirement", "policy", "standard"])
            
            if compliance_risk:
                # Create a compliance concern
                concern = BlackboardEntry(
                    entry_id=f"concern_{uuid.uuid4()}",
                    entry_type=EntryType.COMPLIANCE_CONCERN,
                    content=f"Potential compliance risk identified in: {directive.content}",
                    source=self.role,
                    rule_id="CIA_COMPLIANCE_RISKS",
                    status=EntryStatus.NEW,
                    confidence=0.85,
                    related_entries=[directive.entry_id],
                    metadata={"risk_type": "compliance"}
                )
                new_entries.append(concern)
                
                # Create a solution with compliance recommendations
                solution = BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content=f"Conduct a formal compliance review before implementation and document all regulatory requirements for: {directive.content}",
                    source=self.role,
                    rule_id="CIA_COMPLIANCE_RISKS",
                    status=EntryStatus.RESOLVED,
                    confidence=0.8,
                    related_entries=[directive.entry_id, concern.entry_id],
                    metadata={"action": "compliance_review"}
                )
                new_entries.append(solution)
            
        return new_entries
    
    def _evaluate_control_effectiveness(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Evaluate effectiveness of existing controls"""
        new_entries = []
        
        # Find resolved solutions
        solutions = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.SOLUTION
            and entry.status == EntryStatus.RESOLVED
        ]
        
        for solution in solutions:
            # Evaluate if the solution has adequate controls
            has_controls = any(kw in solution.content.lower() 
                             for kw in ["monitor", "control", "review", "check", "verify", "audit", "oversight"])
            
            if not has_controls:
                # Create a compliance concern
                concern = BlackboardEntry(
                    entry_id=f"concern_{uuid.uuid4()}",
                    entry_type=EntryType.COMPLIANCE_CONCERN,
                    content=f"Inadequate control mechanisms in proposed solution: {solution.content}",
                    source=self.role,
                    rule_id="CIA_CONTROL_EFFECTIVENESS",
                    status=EntryStatus.NEW,
                    confidence=0.9,
                    related_entries=[solution.entry_id],
                    metadata={"issue_type": "control_weakness"}
                )
                new_entries.append(concern)
                
                # Create an improved solution
                improved_solution = BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content=f"Enhance solution with monitoring and control mechanisms: {solution.content}",
                    source=self.role,
                    rule_id="CIA_CONTROL_EFFECTIVENESS",
                    status=EntryStatus.RESOLVED,
                    confidence=0.85,
                    related_entries=[solution.entry_id, concern.entry_id],
                    metadata={"action": "enhance_controls"}
                )
                new_entries.append(improved_solution)
            
        return new_entries
    
    def _recommend_audit_procedures(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Recommend audit procedures for new processes"""
        new_entries = []
        
        # Find new process directives
        new_process_directives = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.DIRECTIVE
            and "new" in entry.content.lower()
            and entry.status in [EntryStatus.NEW, EntryStatus.PROCESSING]
        ]
        
        for directive in new_process_directives:
            # Create audit procedure recommendations
            solution = BlackboardEntry(
                entry_id=f"solution_{uuid.uuid4()}",
                entry_type=EntryType.SOLUTION,
                content=f"Implement the following audit procedures for {directive.content}: 1) Document process flows, 2) Identify key control points, 3) Establish regular compliance checks, 4) Create audit trails for all transactions",
                source=self.role,
                rule_id="CIA_AUDIT_PROCEDURES",
                status=EntryStatus.RESOLVED,
                confidence=0.9,
                related_entries=[directive.entry_id],
                metadata={"action": "audit_procedures"}
            )
            new_entries.append(solution)
            
            # Create a directive for implementation
            audit_directive = BlackboardEntry(
                entry_id=f"directive_{uuid.uuid4()}",
                entry_type=EntryType.DIRECTIVE,
                content=f"Establish audit framework before implementing: {directive.content}",
                source=self.role,
                rule_id="CIA_AUDIT_PROCEDURES",
                status=EntryStatus.NEW,
                confidence=0.85,
                related_entries=[directive.entry_id, solution.entry_id],
                metadata={"action_type": "audit_framework"}
            )
            new_entries.append(audit_directive)
            
        return new_entries
    
    def _flag_fraud_risks(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Flag potential fraud risks in processes"""
        new_entries = []
        
        # Find entries related to financial processes
        financial_entries = [
            entry for entry in blackboard.entries.values()
            if (entry.entry_type == EntryType.SOLUTION or entry.entry_type == EntryType.DIRECTIVE)
            and any(kw in entry.content.lower() for kw in ["approval", "payment", "finance", "budget", "resource"])
        ]
        
        for entry in financial_entries:
            # Check for fraud prevention measures
            has_fraud_prevention = any(kw in entry.content.lower() 
                                     for kw in ["verify", "validate", "authenticate", "authorize", "dual control"])
            
            if not has_fraud_prevention:
                # Create a compliance concern
                concern = BlackboardEntry(
                    entry_id=f"concern_{uuid.uuid4()}",
                    entry_type=EntryType.COMPLIANCE_CONCERN,
                    content=f"Potential fraud risk identified in: {entry.content}",
                    source=self.role,
                    rule_id="CIA_FRAUD_RISKS",
                    status=EntryStatus.NEW,
                    confidence=0.9,
                    related_entries=[entry.entry_id],
                    metadata={"risk_type": "fraud"}
                )
                new_entries.append(concern)
                
                # Create a solution with fraud prevention measures
                solution = BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content=f"Implement fraud prevention measures: 1) Dual control for approvals, 2) Verification of requests, 3) Regular audits, 4) Separation of duties for: {entry.content}",
                    source=self.role,
                    rule_id="CIA_FRAUD_RISKS",
                    status=EntryStatus.RESOLVED,
                    confidence=0.85,
                    related_entries=[entry.entry_id, concern.entry_id],
                    metadata={"action": "fraud_prevention"}
                )
                new_entries.append(solution)
            
        return new_entries
    
    def _ensure_segregation_duties(self, blackboard: Blackboard) -> List[BlackboardEntry]:
        """Ensure proper segregation of duties in processes"""
        new_entries = []
        
        # Find process-related solutions
        process_solutions = [
            entry for entry in blackboard.entries.values()
            if entry.entry_type == EntryType.SOLUTION
            and any(kw in entry.content.lower() for kw in ["process", "procedure", "workflow", "approval"])
            and entry.status == EntryStatus.RESOLVED
        ]
        
        for solution in process_solutions:
            # Check for segregation of duties
            has_segregation = "segregation" in solution.content.lower() or "separation of duties" in solution.content.lower()
            
            if not has_segregation:
                # Create a compliance concern
                concern = BlackboardEntry(
                    entry_id=f"concern_{uuid.uuid4()}",
                    entry_type=EntryType.COMPLIANCE_CONCERN,
                    content=f"Lack of segregation of duties in: {solution.content}",
                    source=self.role,
                    rule_id="CIA_SEGREGATION_DUTIES",
                    status=EntryStatus.NEW,
                    confidence=0.9,
                    related_entries=[solution.entry_id],
                    metadata={"issue_type": "segregation"}
                )
                new_entries.append(concern)
                
                # Create an improved solution
                improved_solution = BlackboardEntry(
                    entry_id=f"solution_{uuid.uuid4()}",
                    entry_type=EntryType.SOLUTION,
                    content=f"Enhance with proper segregation of duties: Ensure that the same person cannot initiate, approve, and review actions in: {solution.content}",
                    source=self.role,
                    rule_id="CIA_SEGREGATION_DUTIES",
                    status=EntryStatus.RESOLVED,
                    confidence=0.8,
                    related_entries=[solution.entry_id, concern.entry_id],
                    metadata={"action": "segregation_of_duties"}
                )
                new_entries.append(improved_solution)
            
        return new_entries

def main():
    """Main function to demonstrate the blackboard expert system"""
    logger.info("Starting Blackboard Expert System for Policy Implementation")
    
    # Create the blackboard
    blackboard = Blackboard()
    
    # Create knowledge sources
    ddg = DeputyDirectorGeneral()
    cia = ChiefInternalAuditor()
    aa = AdministrativeAssistant()
    
    # Create the control shell
    control_shell = ControlShell(blackboard, [ddg, cia, aa])
    
    # Add initial entries to the blackboard
    
    # Issue 1: Approval bottleneck
    blackboard.add_entry(BlackboardEntry(
        entry_id=f"issue_{uuid.uuid4()}",
        entry_type=EntryType.ISSUE,
        content="Approval process for procurement requests takes too long, causing delays in project implementation",
        source=ExpertRole.AA,
        rule_id=None,
        status=EntryStatus.NEW,
        confidence=0.9,
        related_entries=[],
        metadata={"issue_type": "process_delay"}
    ))
    
    # Issue 2: Resource allocation
    blackboard.add_entry(BlackboardEntry(
        entry_id=f"issue_{uuid.uuid4()}",
        entry_type=EntryType.ISSUE,
        content="Shortage of IT resources for implementing the new digital signature system",
        source=ExpertRole.DDG,
        rule_id=None,
        status=EntryStatus.NEW,
        confidence=0.85,
        related_entries=[],
        metadata={"issue_type": "resource_shortage"}
    ))
    
    # Directive 1: New compliance requirement
    blackboard.add_entry(BlackboardEntry(
        entry_id=f"directive_{uuid.uuid4()}",
        entry_type=EntryType.DIRECTIVE,
        content="Implement new data protection policy in accordance with updated regulations",
        source=ExpertRole.DDG,
        rule_id=None,
        status=EntryStatus.NEW,
        confidence=0.95,
        related_entries=[],
        metadata={"directive_type": "compliance"}
    ))
    
    # Directive 2: Process improvement
    blackboard.add_entry(BlackboardEntry(
        entry_id=f"directive_{uuid.uuid4()}",
        entry_type=EntryType.DIRECTIVE,
        content="Create new streamlined process for budget approval to reduce bureaucratic delays",
        source=ExpertRole.DDG,
        rule_id=None,
        status=EntryStatus.NEW,
        confidence=0.9,
        related_entries=[],
        metadata={"directive_type": "process_improvement"}
    ))
    
    # Run the system to completion
    control_shell.run_to_completion()
    
    # Print final summary
    print("\n=== FINAL SYSTEM STATE ===")
    print(f"Total entries: {len(blackboard.entries)}")
    print(f"Reasoning cycles: {control_shell.reasoning_cycles}")
    
    # Count entries by type
    type_counts = {}
    for entry_type in EntryType:
        count = len(blackboard.get_entries_by_type(entry_type))
        if count > 0:
            type_counts[entry_type] = count
    
    print("\nEntries by type:")
    for entry_type, count in type_counts.items():
        print(f"- {entry_type.name}: {count}")

if __name__ == "__main__":
    import time  # Add time import for sleep function
    main()







