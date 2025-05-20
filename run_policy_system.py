"""
Wrapper script to run the policy implementation system.
"""
import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Import the main function from the policy_implementation module
from policy_implementation.main import main

if __name__ == "__main__":
    # Run the main function
    exit(main())
