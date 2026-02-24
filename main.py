from agents.recon_agent.recon_agent import run_recon

if __name__ == "__main__":
    target = input("Enter target (IP / range / domain): ")
    run_recon(target)