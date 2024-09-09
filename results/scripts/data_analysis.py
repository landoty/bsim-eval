import sys
import os
import re
import matplotlib.pyplot as plt

colors = ['dodgerblue', 'forestgreen', 'mediumorchid', 'black']
def evaluate(files: list) -> None:
    fig, axs = plt.subplots(1, 2, tight_layout=False)
    table_stats = {"runs": [], "row_labels": ["Avg. Similarity", "No. of Functions", "No. of Matches", "Accuracy"], \
                                "data": {"avg_sim": [], "no_fns": [], "no_matches": [], "acc": []}}
    for i, f in enumerate(files):
        with open(f, "r") as file:
            sims = []
            confs = []
            no_matches = 0
            no_fns = 0

            db, binary, sim_thresh, conf_thresh = file.readline().strip().split(",")
            for l in file.readlines():
                try:
                    split = l.strip().split(" ")
                    if len(split) > 1:
                        no_fns = int(split[0])
                        match = split[1]
                        matched = False # new group, reset 
                    elif not matched:
                        match = split[0]
                    else:
                        continue # already found a match, continue

                    db_fn, match_fn, sim, conf = re.split(r',(?=")', match)

                except Exception as e:
                    print(e)
                    continue

                if db_fn == match_fn:
                    sims.append(float(sim.replace('"', "")))
                    confs.append(float(conf.replace('"', "")))
                    no_matches += 1
                    matched = True # found a match in the group

            run_name = os.path.basename(f).split(".")[0]

            table_stats["runs"].append(run_name)
            table_stats["data"]["avg_sim"].append(round(sum(sims)/len(sims), 4))
            table_stats["data"]["no_fns"].append(no_fns)
            table_stats["data"]["no_matches"].append(no_matches)
            table_stats["data"]["acc"].append(round(no_matches/no_fns, 4))

            axs[0].hist(sims, alpha=0.7, color=colors[i], label=run_name, bins=10, range=(0.0, 1.0))
            axs[1].scatter(sims, confs, color=colors[i], alpha=0.7)

        axs[0].set_xlabel("similarity")
        axs[0].set_ylabel('# of matches')

        axs[1].set_xlabel("similarity")
        axs[1].set_ylabel("confidence")

    fig.legend()
    plt.savefig("positive-match-correlation.png")

    plt.clf()

    plt.table(cellText=list(table_stats["data"].values()), \
              rowLabels=table_stats["row_labels"], \
              colLabels=table_stats["runs"], \
              colColours=list(zip(colors, [0.5 for i in range(len(colors))])), \
              alpha=0.5, \
              loc='center')

    ax = plt.gca()
    ax.get_xaxis().set_visible(False)
    ax.get_yaxis().set_visible(False)
    plt.box(on=None)

    plt.savefig("match-accuracy.png")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Provide files")
        sys.exit(1)

    files = []
    for f in sys.argv[1:]:
        if os.path.exists(f):
            files.append(f)

    evaluate(files)
