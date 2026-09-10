"""Run Task 8 and Task 9 end-to-end with the approved Task 4 MITRE context."""
from event_correlation import main as correlate
from attack_chain import main as chains

if __name__ == "__main__":
    corr = correlate("m3_task1_inputs.csv", "correlations.csv", "task4_mitre_context.csv")
    chain = chains("correlations.csv", "prioritized_incidents.csv", "attack_chains.csv")
    print(f"Task 8 correlations: {len(corr)}")
    print(f"Task 9 attack chains: {len(chain)}")
