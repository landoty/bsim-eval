import sys
import os
import matplotlib.pyplot as plt

colors = ['dodgerblue', 'forestgreen', 'black']
def evaluate(files: list) -> None:
    fig, axs = plt.subplots(1, 2, tight_layout=False)
    table_stats = {"runs": [], "row_labels": ["Avg. Similarity", "No. of Functions", "No. of Matches", "Accuracy"], \
                                "data": {"avg_sim": [], "no_fns": [], "no_matches": [], "acc": []}}
    for i, f in enumerate(files):
        with open(f, "r") as file:
            sims = []
            confs = []
            total = 0

            db, binary, sim_thresh, conf_thresh = file.readline().strip().split(",")
            for l in file.readlines():
                l = l.strip()
                try: # most lines of this form
                    db_fn, match_fn, sim, conf = l.split(",")
                except: # last line has the total number of functions
                    num = int(l)

                if db_fn == match_fn:
                    sims.append(float(sim))
                    confs.append(float(conf))
                    total += 1

            run_name = os.path.basename(f).split(".")[0]

            table_stats["runs"].append(run_name)
            table_stats["data"]["avg_sim"].append(round(sum(sims)/len(sims), 4))
            table_stats["data"]["no_fns"].append(num)
            table_stats["data"]["no_matches"].append(total)
            table_stats["data"]["acc"].append(round(total/num, 4))

            axs[0].hist(sims, alpha=0.7, histtype='bar', color=colors[i], label=run_name, bins=10, range=(0.0, 1.0))
            axs[1].scatter(sims, confs, color=colors[i], alpha=0.7)

        axs[0].set_xlabel("similarity")
        axs[0].set_ylabel('# of matches')

        axs[1].set_xlabel("similarity")
        axs[1].set_ylabel("confidence")

    fig.legend()
    plt.savefig("postive-match-correlation.png")

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
