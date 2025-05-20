"""
Main entry point for the policy implementation system.
"""
import argparse
import logging
import os
import time
from policy_implementation.core.blackboard import Blackboard
from policy_implementation.repositories.entry_repository import InMemoryEntryRepository
from policy_implementation.repositories.rule_repository import InMemoryRuleRepository
from policy_implementation.reasoning.mediator import BlackboardMediator
from policy_implementation.reasoning.control_shell import ControlShell
from policy_implementation.experts.expert_factory import ExpertFactory
from policy_implementation.reporting.console_report import ConsoleReportGenerator
from policy_implementation.reporting.html_report import HTMLReportGenerator
from policy_implementation.scenarios.scenario_loader import ScenarioLoader
from policy_implementation.utils.observers import BlackboardStatisticsObserver

def setup_logging(log_level=logging.INFO, log_file=None):
    """
    Set up logging
    
    Args:
        log_level: Logging level
        log_file: Optional file to log to
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if log_file:
        logging.basicConfig(level=log_level, format=log_format, filename=log_file)
    else:
        logging.basicConfig(level=log_level, format=log_format)
    
    # Reduce verbosity of some loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)

def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Policy Implementation Expert System")
    
    parser.add_argument("--scenario", default="approval_bottleneck", 
                       help="Scenario to run (default: approval_bottleneck)")
    
    parser.add_argument("--report-format", default="console", 
                       choices=["console", "html", "all"],
                       help="Report format (default: console)")
    
    parser.add_argument("--output-dir", default="./reports", 
                       help="Directory for report output (default: ./reports)")
    
    parser.add_argument("--max-cycles", type=int, default=10,
                       help="Maximum number of reasoning cycles (default: 10)")
    
    parser.add_argument("--log-level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                       help="Logging level (default: INFO)")
    
    parser.add_argument("--log-file", default=None,
                       help="Log file (default: None, log to console)")
    
    return parser.parse_args()

def main():
    """Main function"""
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    
    logger = logging.getLogger("PolicyImplementation")
    logger.info("Starting Policy Implementation Expert System")
    
    # Create repositories
    entry_repo = InMemoryEntryRepository()
    rule_repo = InMemoryRuleRepository()
    
    # Create blackboard
    blackboard = Blackboard()
    
    # Create statistics observer
    stats_observer = BlackboardStatisticsObserver()
    blackboard.register_observer(stats_observer)
    
    # Create mediator
    mediator = BlackboardMediator(blackboard)
    
    # Create experts
    expert_factory = ExpertFactory(rule_repo)
    experts = [
        expert_factory.create_expert("DeputyDirectorGeneral", blackboard, mediator),
        expert_factory.create_expert("ChiefInternalAuditor", blackboard, mediator),
        expert_factory.create_expert("AdministrativeAssistant", blackboard, mediator)
    ]
    
    # Register experts with mediator
    for expert in experts:
        mediator.register_knowledge_source(expert)
    
    # Create control shell
    control_shell = ControlShell(blackboard, experts, mediator)
    control_shell.max_reasoning_cycles = args.max_cycles
    mediator.register_control_shell(control_shell)
    
    # Create report generators
    report_generators = []
    
    if args.report_format in ["console", "all"]:
        console_report = ConsoleReportGenerator(blackboard, mediator)
        report_generators.append(console_report)
        control_shell.add_report_generator(console_report)
    
    if args.report_format in ["html", "all"]:
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        html_report = HTMLReportGenerator(blackboard, mediator, args.output_dir)
        report_generators.append(html_report)
        control_shell.add_report_generator(html_report)
    
    # Register report generators with mediator
    for generator in report_generators:
        mediator.register_report_generator(generator)
    
    # Load scenario
    scenario_loader = ScenarioLoader(blackboard)
    if not scenario_loader.load_scenario(args.scenario):
        logger.error(f"Failed to load scenario: {args.scenario}")
        return 1
    
    # Run the system
    logger.info(f"Running scenario: {args.scenario}")
    start_time = time.time()
    control_shell.run_to_completion()
    end_time = time.time()
    
    # Print statistics
    logger.info(f"Execution complete in {end_time - start_time:.2f} seconds")
    stats = stats_observer.get_statistics()
    logger.info(f"Event counts: {stats['event_counts']}")
    logger.info(f"Entry type counts: {stats['entry_type_counts']}")
    logger.info(f"Source counts: {stats['source_counts']}")
    
    return 0

if __name__ == "__main__":
    exit(main())
