"""
Control shell for managing the reasoning process.
"""
import logging
import time
from typing import List, Dict, Any, Optional
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.entry import BlackboardEntry
from policy_implementation.core.enums import EntryStatus, EntryType

logger = logging.getLogger(__name__)

class ControlShell:
    """Control shell that manages the reasoning process"""
    
    def __init__(self, 
                 blackboard: BlackboardInterface, 
                 knowledge_sources: List, 
                 mediator=None):
        """
        Initialize the control shell
        
        Args:
            blackboard: Blackboard to manage
            knowledge_sources: Knowledge sources to activate
            mediator: Optional mediator for communication
        """
        self.blackboard = blackboard
        self.knowledge_sources = knowledge_sources
        self.mediator = mediator
        self.reasoning_cycles = 0
        self.max_reasoning_cycles = 10
        self.consecutive_cycles_without_changes = 0
        self.max_cycles_without_changes = 3
        self.report_generators = []
        self.unaddressed_entries = set()
    
    def set_mediator(self, mediator) -> None:
        """
        Set the mediator for this control shell
        
        Args:
            mediator: Mediator to use
        """
        self.mediator = mediator
    
    def add_report_generator(self, generator) -> None:
        """
        Add a report generator
        
        Args:
            generator: Report generator to add
        """
        self.report_generators.append(generator)
    
    def generate_reports(self) -> Dict[str, str]:
        """
        Generate reports from all registered generators
        
        Returns:
            Dict[str, str]: Dictionary of report name -> report content
        """
        reports = {}
        for generator in self.report_generators:
            reports[generator.__class__.__name__] = generator.generate_report()
        return reports
    
    def run_reasoning_cycle(self) -> bool:
        """
        Run a single reasoning cycle
        
        Returns:
            bool: True if the reasoning process should continue
        """
        logger.info(f"Starting reasoning cycle {self.reasoning_cycles + 1}")
        
        # Track initial blackboard state
        initial_entry_count = len(self.blackboard.entries)
        
        # Get available knowledge sources
        if self.mediator:
            available_ks = self.mediator.get_available_knowledge_sources()
        else:
            available_ks = [ks for ks in self.knowledge_sources if ks.is_available()]
        
        # Sort by priority
        available_ks.sort(key=lambda ks: ks.priority, reverse=True)
        
        # Activate each knowledge source
        for ks in available_ks:
            if self.mediator:
                new_entries = self.mediator.activate_knowledge_source(ks)
            else:
                new_entries = ks.activate(self.blackboard)
            
            if new_entries:
                logger.info(f"Knowledge source {ks.name} created {len(new_entries)} new entries")
                
                # Process conflicts for new entries
                for entry in new_entries:
                    self._process_entry(entry)
        
        # Check if any changes were made
        final_entry_count = len(self.blackboard.entries)
        if final_entry_count > initial_entry_count:
            self.consecutive_cycles_without_changes = 0
        else:
            self.consecutive_cycles_without_changes += 1
        
        # Increment cycle counter
        self.reasoning_cycles += 1
        
        # Check if we should continue
        return self._should_continue()
    
    def run_to_completion(self) -> Dict[str, str]:
        """
        Run the reasoning process until completion
        
        Returns:
            Dict[str, str]: Dictionary of report name -> report content
        """
        while self.run_reasoning_cycle():
            time.sleep(0.5)
        
        logger.info("=== Reasoning process complete ===")
        
        # Generate reports
        reports = self.generate_reports()
        
        return reports
    
    def _process_entry(self, entry: BlackboardEntry) -> None:
        """
        Process a new entry
        
        Args:
            entry: Entry to process
        """
        # Detect conflicts
        conflicts = self._detect_conflicts(entry)
        
        if conflicts:
            # Resolve conflicts
            resolved_entry = self._resolve_conflicts(entry, conflicts)
            
            # If the entry was rejected, don't process it further
            if resolved_entry.status == EntryStatus.REJECTED:
                return
        
        # Track unaddressed entries
        if entry.entry_type in [EntryType.ISSUE, EntryType.COMPLIANCE_CONCERN]:
            self.unaddressed_entries.add(entry.entry_id)
        
        # If this entry addresses other entries, mark them as addressed
        if entry.entry_type in [EntryType.SOLUTION, EntryType.DECISION]:
            for related_id in entry.related_entries:
                if related_id in self.unaddressed_entries:
                    self.unaddressed_entries.remove(related_id)
    
    def _detect_conflicts(self, new_entry: BlackboardEntry) -> List[BlackboardEntry]:
        """
        Detect conflicts between a new entry and existing entries
        
        Args:
            new_entry: The new entry to check for conflicts
            
        Returns:
            List[BlackboardEntry]: List of conflicting entries
        """
        conflicts = []
        
        # Only certain entry types can conflict
        if new_entry.entry_type in [EntryType.SOLUTION, EntryType.DECISION, EntryType.DIRECTIVE]:
            # Check for entries of the same type with different solutions
            similar_entries = self.blackboard.get_entries_by_type(new_entry.entry_type)
            
            for entry in similar_entries:
                # Skip entries that are already rejected
                if entry.status == EntryStatus.REJECTED:
                    continue
                    
                # Skip comparing with self
                if entry.entry_id == new_entry.entry_id:
                    continue
                
                # Enhanced conflict detection:
                # 1. If they relate to the same issues but have different content
                # 2. If they have very similar content but different sources
                # 3. If they have contradictory recommendations
                
                # Check for overlapping related entries
                related_overlap = bool(set(entry.related_entries) & set(new_entry.related_entries))
                
                # Check for contradictory content
                contradictory = False
                if new_entry.entry_type == EntryType.DECISION:
                    # For decisions, check if they recommend opposite actions
                    approve_keywords = ["approve", "accept", "proceed", "implement"]
                    reject_keywords = ["reject", "deny", "decline", "stop", "halt"]
                    
                    new_approves = any(kw in new_entry.content.lower() for kw in approve_keywords)
                    new_rejects = any(kw in new_entry.content.lower() for kw in reject_keywords)
                    entry_approves = any(kw in entry.content.lower() for kw in approve_keywords)
                    entry_rejects = any(kw in entry.content.lower() for kw in reject_keywords)
                    
                    contradictory = (new_approves and entry_rejects) or (new_rejects and entry_approves)
                
                # If there's a conflict, add it to the list
                if (related_overlap and entry.content != new_entry.content) or contradictory:
                    conflicts.append(entry)
        
        return conflicts
    
    def _resolve_conflicts(self, new_entry: BlackboardEntry, conflicts: List[BlackboardEntry]) -> BlackboardEntry:
        """
        Resolve conflicts between entries
        
        Args:
            new_entry: The new entry
            conflicts: List of conflicting entries
            
        Returns:
            BlackboardEntry: The resolved entry
        """
        if not conflicts:
            return new_entry
        
        logger.info(f"Resolving conflicts for entry {new_entry.entry_id} with {len(conflicts)} conflicts")
        
        # Strategy 1: Check for complementary solutions that can be merged
        if new_entry.entry_type == EntryType.SOLUTION:
            # Try to merge complementary solutions
            merged_solution = self._try_merge_solutions(new_entry, conflicts)
            if merged_solution:
                logger.info(f"Merged solutions into {merged_solution.entry_id}")
                return merged_solution
        
        # Strategy 2: Role-based priority
        from policy_implementation.core.enums import PRIORITY_LEVELS
        
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
        
        # Strategy 3: Use confidence scores if priorities are equal
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
        
        # Strategy 4: For decisions, prefer the most recent one if from same source
        if new_entry.entry_type == EntryType.DECISION:
            same_source_conflicts = [c for c in conflicts if c.source == new_entry.source]
            if same_source_conflicts:
                # The newer decision from the same source supersedes older ones
                for conflict in same_source_conflicts:
                    self.blackboard.update_entry(
                        conflict.entry_id, 
                        status=EntryStatus.REJECTED,
                        metadata={**conflict.metadata, "rejected_by": new_entry.entry_id, 
                                 "rejection_reason": "Superseded by newer decision"}
                    )
                # Remove the resolved conflicts
                conflicts = [c for c in conflicts if c.source != new_entry.source]
                if not conflicts:
                    return new_entry
        
        # Strategy 5: If still tied, escalate for human intervention
        new_entry.status = EntryStatus.NEEDS_CLARIFICATION
        new_entry.metadata["conflict_with"] = [conflict.entry_id for conflict in conflicts]
        
        return new_entry
    
    def _try_merge_solutions(self, new_solution: BlackboardEntry, conflicts: List[BlackboardEntry]) -> Optional[BlackboardEntry]:
        """
        Try to merge complementary solutions
        
        Args:
            new_solution: The new solution entry
            conflicts: List of conflicting solution entries
            
        Returns:
            BlackboardEntry or None: A merged solution entry if possible, None otherwise
        """
        import uuid
        
        # Only attempt to merge solutions
        if new_solution.entry_type != EntryType.SOLUTION:
            return None
            
        # Find solutions that might be complementary (addressing same issues)
        complementary = []
        for conflict in conflicts:
            # Skip if not a solution
            if conflict.entry_type != EntryType.SOLUTION:
                continue
                
            # Check if they address the same issues
            if set(conflict.related_entries) == set(new_solution.related_entries):
                # Check if they're not contradictory (e.g., one says "approve", other says "reject")
                approve_keywords = ["approve", "accept", "proceed", "implement"]
                reject_keywords = ["reject", "deny", "decline", "stop", "halt"]
                
                new_approves = any(kw in new_solution.content.lower() for kw in approve_keywords)
                new_rejects = any(kw in new_solution.content.lower() for kw in reject_keywords)
                conflict_approves = any(kw in conflict.content.lower() for kw in approve_keywords)
                conflict_rejects = any(kw in conflict.content.lower() for kw in reject_keywords)
                
                contradictory = (new_approves and conflict_rejects) or (new_rejects and conflict_approves)
                
                if not contradictory:
                    complementary.append(conflict)
        
        if not complementary:
            return None
            
        # Create a merged solution
        merged_content = new_solution.content
        merged_confidence = new_solution.confidence
        merged_metadata = dict(new_solution.metadata)
        merged_related = list(new_solution.related_entries)
        
        # Add unique points from complementary solutions
        for solution in complementary:
            # Extract key points from the solution content
            # This is a simple approach - in a real system, you'd use NLP to extract key points
            solution_points = solution.content.split(',')
            for point in solution_points:
                point = point.strip()
                if point and point not in merged_content:
                    merged_content += f"\n- {point}"
            
            # Update confidence as a weighted average
            merged_confidence = (merged_confidence + solution.confidence) / 2
            
            # Merge metadata
            for key, value in solution.metadata.items():
                if key not in merged_metadata:
                    merged_metadata[key] = value
            
            # Add any unique related entries
            for rel in solution.related_entries:
                if rel not in merged_related:
                    merged_related.append(rel)
                    
            # Mark the complementary solution as merged
            self.blackboard.update_entry(
                solution.entry_id,
                status=EntryStatus.RESOLVED,
                metadata={**solution.metadata, "merged_into": new_solution.entry_id}
            )
        
        # Create the merged solution entry
        merged_solution = BlackboardEntry(
            entry_id=f"merged_solution_{uuid.uuid4()}",
            entry_type=EntryType.SOLUTION,
            content=f"Merged solution: {merged_content}",
            source=new_solution.source,
            rule_id=new_solution.rule_id,
            status=EntryStatus.RESOLVED,
            confidence=merged_confidence,
            related_entries=merged_related,
            metadata={**merged_metadata, "merged_from": [new_solution.entry_id] + [s.entry_id for s in complementary]}
        )
        
        # Add the merged solution to the blackboard
        self.blackboard.add_entry(merged_solution)
        
        return merged_solution
    
    def _should_continue(self) -> bool:
        """
        Determine if the reasoning process should continue
        
        Returns:
            bool: True if the reasoning process should continue
        """
        # Stop if maximum cycles reached
        if self.reasoning_cycles >= self.max_reasoning_cycles:
            logger.info(f"Reached maximum reasoning cycles ({self.max_reasoning_cycles})")
            return False
        
        # Stop if no changes for several consecutive cycles
        if self.consecutive_cycles_without_changes >= self.max_cycles_without_changes:
            logger.info(f"No changes for {self.consecutive_cycles_without_changes} consecutive cycles")
            return False
        
        # Stop if all entries are resolved, rejected, or escalated
        terminal_statuses = [EntryStatus.RESOLVED, EntryStatus.REJECTED, EntryStatus.ESCALATED]
        open_entries = [
            entry for entry in self.blackboard.entries.values()
            if entry.status not in terminal_statuses
        ]
        
        if not open_entries:
            logger.info("All entries have reached a terminal status")
            return False
            
        # Check if we've made progress on the original issues
        original_issues = [
            entry for entry in self.blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE and entry.rule_id is None
        ]
        
        # If all original issues have solutions, we can stop
        if original_issues:
            all_issues_addressed = True
            for issue in original_issues:
                # Find solutions that address this issue
                solutions = [
                    entry for entry in self.blackboard.entries.values()
                    if entry.entry_type == EntryType.SOLUTION 
                    and issue.entry_id in entry.related_entries
                    and entry.status == EntryStatus.RESOLVED
                ]
                
                if not solutions:
                    all_issues_addressed = False
                    break
            
            if all_issues_addressed:
                logger.info("All original issues have been addressed with solutions")
                return False
        
        # Check if we're making progress or just generating redundant entries
        if self.reasoning_cycles > 3:  # Give the system a few cycles to get going
            # Calculate the rate of new unique entries
            total_entries = len(self.blackboard.entries)
            unique_content_count = len(getattr(self.blackboard, 'content_hash_map', {}))
            
            # If we have a lot of entries but few unique ones, we're generating redundancy
            if total_entries > 20 and unique_content_count > 0 and unique_content_count / total_entries < 0.5:
                logger.info(f"High redundancy detected: {unique_content_count} unique entries out of {total_entries} total")
                return False
        
        return True
    
    def on_blackboard_event(self, event_type: str, data: Any) -> None:
        """
        Handle blackboard events
        
        Args:
            event_type: Type of event
            data: Data associated with the event
        """
        if event_type == "entry_added":
            self._process_entry(data)
        elif event_type == "entry_updated":
            # Handle entry updates if needed
            pass
