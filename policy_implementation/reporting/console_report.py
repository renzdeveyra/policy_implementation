"""
Console report generator for the policy implementation system.
"""
from typing import List, Dict, Any
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole
from policy_implementation.reporting.report_generator import ReportGenerator

class ConsoleReportGenerator(ReportGenerator):
    """Generates reports for console output"""
    
    def generate_report(self) -> str:
        """
        Generate a console report
        
        Returns:
            str: The generated report
        """
        report = []
        report.append("\n" + "=" * 60)
        report.append("POLICY IMPLEMENTATION BOTTLENECK RESOLUTION REPORT")
        report.append("=" * 60)
        
        # Add summary statistics
        report.append("\n1. SUMMARY STATISTICS")
        report.append("-" * 30)
        
        # Count active vs. rejected entries
        active_entries = self.get_active_entries()
        rejected_entries = self.get_rejected_entries()
        
        report.append(f"Total entries: {len(self.blackboard.entries)}")
        report.append(f"Active entries: {len(active_entries)}")
        report.append(f"Rejected/superseded entries: {len(rejected_entries)}")
        
        # Count entries by type (only active entries)
        type_counts = {}
        for entry_type in EntryType:
            count = len([e for e in active_entries if e.entry_type == entry_type])
            if count > 0:
                type_counts[entry_type] = count
        
        report.append("\nActive entries by type:")
        for entry_type, count in type_counts.items():
            report.append(f"- {entry_type.name}: {count}")
        
        # Count entries by status
        status_counts = {}
        for status in EntryStatus:
            count = len([e for e in active_entries if e.status == status])
            if count > 0:
                status_counts[status] = count
        
        report.append("\nEntries by status:")
        for status, count in status_counts.items():
            report.append(f"- {status.name}: {count}")
        
        # Count entries by source
        source_counts = {}
        for source in ExpertRole:
            count = len([e for e in active_entries if e.source == source])
            if count > 0:
                source_counts[source] = count
        
        report.append("\nContributions by expert:")
        for source, count in source_counts.items():
            report.append(f"- {source.name}: {count}")
        
        # Solutions and decisions
        report.append("\n2. RECOMMENDED ACTIONS")
        report.append("-" * 30)
        
        # Get original issues to organize solutions by the issues they address
        original_issues = [
            entry for entry in self.blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE and entry.rule_id is None
        ]
        
        # Get solutions by issue
        solutions_by_issue = self.get_solutions_by_issue()
        
        # Print solutions organized by issue
        if original_issues:
            report.append("\nRecommended Solutions by Issue:")
            for i, issue in enumerate(original_issues, 1):
                report.append(f"\nIssue {i}: {issue.content}")
                report.append(f"Status: {issue.status.name}")
                
                issue_solutions = solutions_by_issue[issue.entry_id]
                if issue_solutions:
                    report.append("Solutions:")
                    # Group solutions by source to reduce redundancy
                    solutions_by_source = {}
                    for solution in issue_solutions:
                        source = solution.source.name if solution.source else "Unknown"
                        if source not in solutions_by_source:
                            solutions_by_source[source] = []
                        solutions_by_source[source].append(solution)
                    
                    # Print consolidated solutions by source
                    for source, source_solutions in solutions_by_source.items():
                        report.append(f"  From {source}:")
                        # Extract unique points from all solutions from this source
                        all_points = set()
                        for solution in source_solutions:
                            # Check if it's a merged solution
                            if solution.content.startswith("Merged solution:"):
                                # Extract points from merged solution
                                points = solution.content.split("\n")[1:]
                                for point in points:
                                    if point.strip() and point.strip() not in all_points:
                                        all_points.add(point.strip())
                            else:
                                # Regular solution
                                all_points.add(solution.content)
                        
                        # Print unique points
                        for j, point in enumerate(all_points, 1):
                            report.append(f"    {j}. {point}")
                else:
                    report.append("  No solutions proposed yet")
        
        # Get decisions by source
        decisions_by_source = self.get_decisions_by_source()
        
        # Print key decisions (avoiding redundancy)
        if decisions_by_source:
            report.append("\nKey Decisions:")
            
            for source, decisions in decisions_by_source.items():
                report.append(f"\nFrom {source}:")
                
                # Group decisions by content similarity to avoid redundancy
                decision_groups = {}
                for decision in decisions:
                    # Create a simplified version of the content for grouping
                    simplified = ' '.join(decision.content.lower().split())
                    found_group = False
                    
                    # Check if this decision fits in an existing group
                    for key in decision_groups:
                        if simplified in key or key in simplified:
                            decision_groups[key].append(decision)
                            found_group = True
                            break
                    
                    # If not found in any group, create a new one
                    if not found_group:
                        decision_groups[simplified] = [decision]
                
                # Print one representative decision from each group
                for i, (_, group) in enumerate(decision_groups.items(), 1):
                    # Use the highest confidence decision as representative
                    representative = max(group, key=lambda d: d.confidence)
                    report.append(f"  {i}. {representative.content}")
                    if len(group) > 1:
                        report.append(f"     (Similar decisions: {len(group)})")
        
        # Unresolved issues
        unresolved_issues = [
            entry for entry in self.blackboard.get_entries_by_type(EntryType.ISSUE)
            if entry.status not in [EntryStatus.RESOLVED, EntryStatus.REJECTED]
        ]
        
        if unresolved_issues:
            report.append("\n3. UNRESOLVED ISSUES")
            report.append("-" * 30)
            for i, issue in enumerate(unresolved_issues, 1):
                report.append(f"\n{i}. {issue.content}")
                report.append(f"   Status: {issue.status.name}")
                
                # Show partial progress
                related_solutions = [
                    entry for entry in self.blackboard.entries.values()
                    if entry.entry_type == EntryType.SOLUTION 
                    and issue.entry_id in entry.related_entries
                ]
                
                if related_solutions:
                    report.append(f"   Partial solutions proposed: {len(related_solutions)}")
        
        # Conflicts detected
        conflict_entries = [
            entry for entry in self.blackboard.entries.values()
            if entry.status == EntryStatus.NEEDS_CLARIFICATION
        ]
        
        if conflict_entries:
            report.append("\n4. CONFLICTS REQUIRING HUMAN INTERVENTION")
            report.append("-" * 30)
            for i, entry in enumerate(conflict_entries, 1):
                report.append(f"\n{i}. {entry.content}")
                if "conflict_with" in entry.metadata:
                    conflict_ids = entry.metadata["conflict_with"]
                    conflicts = [self.blackboard.get_entry(cid) for cid in conflict_ids]
                    report.append("   Conflicts with:")
                    for conflict in conflicts:
                        if conflict:
                            report.append(f"   - {conflict.content}")
                            if conflict.source:
                                report.append(f"     (From: {conflict.source.name})")
        
        # Add a section for implementation recommendations
        report.append("\n5. IMPLEMENTATION RECOMMENDATIONS")
        report.append("-" * 30)
        report.append("\nBased on the analysis, the following implementation approach is recommended:")
        
        # Extract key recommendations from solutions
        key_recommendations = set()
        for solution in [e for e in self.blackboard.entries.values() 
                        if e.entry_type == EntryType.SOLUTION and e.status == EntryStatus.RESOLVED]:
            if "action" in solution.metadata:
                action_type = solution.metadata["action"]
                if action_type == "streamline_approvals":
                    key_recommendations.add("Implement a streamlined approval process with delegation of authority")
                elif action_type == "resource_reallocation":
                    key_recommendations.add("Reallocate resources from lower priority projects")
                elif action_type == "compliance_review":
                    key_recommendations.add("Conduct formal compliance reviews before implementation")
                elif action_type == "procedure_improvement":
                    key_recommendations.add("Create standardized procedures for handling exceptions")
        
        # Print key recommendations
        for i, recommendation in enumerate(key_recommendations, 1):
            report.append(f"{i}. {recommendation}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
