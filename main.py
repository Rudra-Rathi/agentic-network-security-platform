from agents.recon_agent.recon_agent import run_recon

if __name__ == "__main__":
    print("Welcome to starting of this project")
    print("-------------------------------------")
    print("-------------------------------------")
    print("-------------------------------------")
    target = input("Enter target (IP / range / domain): ")
    
    run_recon(target)