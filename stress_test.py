# mypy: ignore-errors
import asyncio
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from chronos_agent import ChronosAgentFactory  # noqa: E402

NUM_AGENTS = 5
MISSION_DURATION = 15


async def run_single_agent(agent_id: int):
    print(f"[Agent {agent_id}] Booting up...")
    start_time = time.time()

    agent = ChronosAgentFactory.create(MISSION_DURATION)

    # Run the full async state machine
    await agent.run_mission()

    end_time = time.time()
    elapsed = end_time - start_time
    print(f"[Agent {agent_id}] Mission Complete. Elapsed: {elapsed:.2f}s")

    return {
        "agent_id": agent_id,
        "elapsed_time_sec": elapsed,
        "fhe_key_size_bits": agent.fhe_engine.crypto.pub_key.n.bit_length(),
        "posw_target_duration": MISSION_DURATION,
    }


async def stress_test():
    print("=== INITIATING CHRONOS STRESS TEST ===")
    print(f"Spawning {NUM_AGENTS} concurrent autonomous agents...")
    print(f"Target Mission Duration: {MISSION_DURATION}s")
    print("Warning: CPU will spike to 100% as multiprocessing processes spin up.")

    global_start = time.time()

    # Spawn multiple agents concurrently
    tasks = [run_single_agent(i) for i in range(NUM_AGENTS)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    global_end = time.time()

    successes = []
    failures = []

    for r in results:
        if isinstance(r, Exception):
            failures.append(str(r))
        else:
            successes.append(r)

    print("\n=== STRESS TEST RESULTS ===")
    print(f"Total Wall Clock Time: {global_end - global_start:.2f}s")
    print(f"Successful Agents: {len(successes)} / {NUM_AGENTS}")
    print(f"Failed Agents: {len(failures)}")

    if successes:
        avg_time = statistics.mean([s["elapsed_time_sec"] for s in successes])
        print(
            f"Average Agent Lifecycle: {avg_time:.2f}s (Expected ~{MISSION_DURATION}s)"
        )

    # Output structured data for artifact generation
    with open("stress_metrics.json", "w") as f:
        json.dump(
            {
                "total_agents": NUM_AGENTS,
                "mission_duration": MISSION_DURATION,
                "wall_clock_time": global_end - global_start,
                "successes": len(successes),
                "failures": len(failures),
                "agents_data": successes,
            },
            f,
            indent=4,
        )


if __name__ == "__main__":
    asyncio.run(stress_test())
