"""
HTML report generator for the policy implementation system.
"""
import os
from datetime import datetime
from typing import List, Dict, Any
from policy_implementation.core.blackboard import BlackboardInterface
from policy_implementation.core.enums import EntryType, EntryStatus, ExpertRole
from policy_implementation.reporting.report_generator import ReportGenerator

class HTMLReportGenerator(ReportGenerator):
    """Generates HTML reports"""
    
    def __init__(self, blackboard: BlackboardInterface, mediator=None, output_dir="./reports"):
        """
        Initialize the HTML report generator
        
        Args:
            blackboard: Blackboard to generate reports for
            mediator: Optional mediator for communication
            output_dir: Directory to save reports to
        """
        super().__init__(blackboard, mediator)
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self) -> str:
        """
        Generate an HTML report
        
        Returns:
            str: The generated report
        """
        html = ["<!DOCTYPE html>"]
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("  <meta charset='UTF-8'>")
        html.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("  <title>Policy Implementation Report</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }")
        html.append("    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }")
        html.append("    h2 { color: #2980b9; margin-top: 30px; }")
        html.append("    h3 { color: #3498db; }")
        html.append("    .section { margin-bottom: 30px; }")
        html.append("    .stats { display: flex; flex-wrap: wrap; gap: 20px; }")
        html.append("    .stat-card { background: #f8f9fa; border-radius: 5px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; min-width: 200px; }")
        html.append("    .stat-value { font-size: 24px; font-weight: bold; color: #2980b9; }")
        html.append("    .issue { background: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin-bottom: 20px; }")
        html.append("    .solution { background: #f1f9f1; border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0 10px 20px; }")
        html.append("    .decision { background: #f9f6f1; border-left: 4px solid #f39c12; padding: 15px; margin-bottom: 15px; }")
        html.append("    .conflict { background: #f9f1f1; border-left: 4px solid #e74c3c; padding: 15px; margin-bottom: 15px; }")
        html.append("    .recommendation { background: #f1f1f9; border-left: 4px solid #9b59b6; padding: 15px; margin-bottom: 15px; }")
        html.append("    .source { font-style: italic; color: #7f8c8d; }")
        html.append("    .footer { margin-top: 50px; border-top: 1px solid #eee; padding-top: 20px; color: #7f8c8d; font-size: 0.9em; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        
        # Header
        html.append("  <h1>Policy Implementation Bottleneck Resolution Report</h1>")
        html.append(f"  <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        
        # Summary Statistics
        html.append("  <div class='section'>")
        html.append("    <h2>1. Summary Statistics</h2>")
        
        # Count active vs. rejected entries
        active_entries = self.get_active_entries()
        rejected_entries = self.get_rejected_entries()
        
        html.append("    <div class='stats'>")
        html.append("      <div class='stat-card'>")
        html.append("        <div>Total Entries</div>")
        html.append(f"        <div class='stat-value'>{len(self.blackboard.entries)}</div>")
        html.append("      </div>")
        html.append("      <div class='stat-card'>")
        html.append("        <div>Active Entries</div>")
        html.append(f"        <div class='stat-value'>{len(active_entries)}</div>")
        html.append("      </div>")
        html.append("      <div class='stat-card'>")
        html.append("        <div>Rejected Entries</div>")
        html.append(f"        <div class='stat-value'>{len(rejected_entries)}</div>")
        html.append("      </div>")
        html.append("    </div>")
        
        # Entries by type
        html.append("    <h3>Entries by Type</h3>")
        html.append("    <div class='stats'>")
        for entry_type in EntryType:
            count = len([e for e in active_entries if e.entry_type == entry_type])
            if count > 0:
                html.append("      <div class='stat-card'>")
                html.append(f"        <div>{entry_type.name}</div>")
                html.append(f"        <div class='stat-value'>{count}</div>")
                html.append("      </div>")
        html.append("    </div>")
        
        # Contributions by expert
        html.append("    <h3>Contributions by Expert</h3>")
        html.append("    <div class='stats'>")
        for source in ExpertRole:
            count = len([e for e in active_entries if e.source == source])
            if count > 0:
                html.append("      <div class='stat-card'>")
                html.append(f"        <div>{source.name}</div>")
                html.append(f"        <div class='stat-value'>{count}</div>")
                html.append("      </div>")
        html.append("    </div>")
        html.append("  </div>")
        
        # Recommended Actions
        html.append("  <div class='section'>")
        html.append("    <h2>2. Recommended Actions</h2>")
        
        # Get original issues to organize solutions by the issues they address
        original_issues = [
            entry for entry in self.blackboard.entries.values()
            if entry.entry_type == EntryType.ISSUE and entry.rule_id is None
        ]
        
        # Get solutions by issue
        solutions_by_issue = self.get_solutions_by_issue()
        
        # Print solutions organized by issue
        if original_issues:
            html.append("    <h3>Recommended Solutions by Issue</h3>")
            
            for i, issue in enumerate(original_issues, 1):
                html.append(f"    <div class='issue'>")
                html.append(f"      <h4>Issue {i}: {issue.content}</h4>")
                html.append(f"      <p>Status: {issue.status.name}</p>")
                
                issue_solutions = solutions_by_issue[issue.entry_id]
                if issue_solutions:
                    # Group solutions by source to reduce redundancy
                    solutions_by_source = {}
                    for solution in issue_solutions:
                        source = solution.source.name if solution.source else "Unknown"
                        if source not in solutions_by_source:
                            solutions_by_source[source] = []
                        solutions_by_source[source].append(solution)
                    
                    # Print consolidated solutions by source
                    for source, source_solutions in solutions_by_source.items():
                        html.append(f"      <div class='solution'>")
                        html.append(f"        <h5>From {source}:</h5>")
                        html.append(f"        <ul>")
                        
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
                        for point in all_points:
                            html.append(f"          <li>{point}</li>")
                        
                        html.append(f"        </ul>")
                        html.append(f"      </div>")
                else:
                    html.append("      <p>No solutions proposed yet</p>")
                
                html.append("    </div>")
        
        # Get decisions by source
        decisions_by_source = self.get_decisions_by_source()
        
        # Print key decisions (avoiding redundancy)
        if decisions_by_source:
            html.append("    <h3>Key Decisions</h3>")
            
            for source, decisions in decisions_by_source.items():
                html.append(f"    <h4>From {source}:</h4>")
                
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
                    html.append(f"    <div class='decision'>")
                    html.append(f"      <p>{representative.content}</p>")
                    if len(group) > 1:
                        html.append(f"      <p class='source'>(Similar decisions: {len(group)})</p>")
                    html.append(f"    </div>")
        
        html.append("  </div>")
        
        # Unresolved Issues
        unresolved_issues = [
            entry for entry in self.blackboard.get_entries_by_type(EntryType.ISSUE)
            if entry.status not in [EntryStatus.RESOLVED, EntryStatus.REJECTED]
        ]
        
        if unresolved_issues:
            html.append("  <div class='section'>")
            html.append("    <h2>3. Unresolved Issues</h2>")
            
            for i, issue in enumerate(unresolved_issues, 1):
                html.append(f"    <div class='issue'>")
                html.append(f"      <h4>Issue {i}: {issue.content}</h4>")
                html.append(f"      <p>Status: {issue.status.name}</p>")
                
                # Show partial progress
                related_solutions = [
                    entry for entry in self.blackboard.entries.values()
                    if entry.entry_type == EntryType.SOLUTION 
                    and issue.entry_id in entry.related_entries
                ]
                
                if related_solutions:
                    html.append(f"      <p>Partial solutions proposed: {len(related_solutions)}</p>")
                
                html.append("    </div>")
            
            html.append("  </div>")
        
        # Conflicts
        conflict_entries = [
            entry for entry in self.blackboard.entries.values()
            if entry.status == EntryStatus.NEEDS_CLARIFICATION
        ]
        
        if conflict_entries:
            html.append("  <div class='section'>")
            html.append("    <h2>4. Conflicts Requiring Human Intervention</h2>")
            
            for i, entry in enumerate(conflict_entries, 1):
                html.append(f"    <div class='conflict'>")
                html.append(f"      <h4>Conflict {i}: {entry.content}</h4>")
                
                if "conflict_with" in entry.metadata:
                    conflict_ids = entry.metadata["conflict_with"]
                    conflicts = [self.blackboard.get_entry(cid) for cid in conflict_ids]
                    html.append("      <p>Conflicts with:</p>")
                    html.append("      <ul>")
                    
                    for conflict in conflicts:
                        if conflict:
                            html.append(f"        <li>{conflict.content}")
                            if conflict.source:
                                html.append(f" <span class='source'>(From: {conflict.source.name})</span>")
                            html.append("</li>")
                    
                    html.append("      </ul>")
                
                html.append("    </div>")
            
            html.append("  </div>")
        
        # Implementation Recommendations
        html.append("  <div class='section'>")
        html.append("    <h2>5. Implementation Recommendations</h2>")
        html.append("    <p>Based on the analysis, the following implementation approach is recommended:</p>")
        
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
        for recommendation in key_recommendations:
            html.append(f"    <div class='recommendation'>")
            html.append(f"      <p>{recommendation}</p>")
            html.append("    </div>")
        
        html.append("  </div>")
        
        # Footer
        html.append("  <div class='footer'>")
        html.append("    <p>Generated by Policy Implementation Expert System</p>")
        html.append("  </div>")
        
        html.append("</body>")
        html.append("</html>")
        
        # Save the report to a file
        report_content = "\n".join(html)
        report_path = os.path.join(self.output_dir, f"policy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        return report_content
