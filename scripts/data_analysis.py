import sys
import os
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def plot(to_plot: dict, to_table: dict) -> None:
    colors = ["dodgerblue", "forestgreen", "mediumorchid", "black"]
    fig, axs = plt.subplots(1,2,tight_layout=False)

    axs[0].hist(
        to_plot["data"]["sims"],
        alpha=0.7,
        color=colors[0:len(to_plot["data"]["sims"])],
        label=to_plot["runs"],
        bins=10,
        range=(0.0,1.0)
    )
    axs[0].set_xlabel("similarity")
    axs[0].set_ylabel("# of matches")
    axs[0].set_title("Correct Match Similarity Distr.")

    for i in range(len(to_plot["data"]["sims"])):
        axs[1].scatter(
            to_plot["data"]["sims"][i],
            to_plot["data"]["confs"][i],
            color=colors[i],
            alpha=0.7)
        axs[1].set_xlabel("similarity")
        axs[1].set_ylabel("confidence")
        axs[1].set_title("Correct Match Similarity v. Confidence")

    fig.legend()
    plt.savefig("positive-match-correlation.png")

    plt.clf()
    plt.table(
        cellText=list(to_table["data"].values()),
        rowLabels=to_table["row_labels"],
        colLabels=to_table["runs"],
        colColours=list(zip(colors, [0.5 for i in range(len(colors))])),
        alpha=0.5,
        loc='center'
    )
    ax = plt.gca()
    ax.get_xaxis().set_visible(False)
    ax.get_yaxis().set_visible(False)
    plt.box(on=None)
    ax.set_title("Match Accuracy")
    plt.savefig("match-accuracy.png")

def analyze(files: list) -> None:
    table_stats = {
        "runs": [],
        "row_labels": [
            "No. of Functions",
            "Top1 Acc.",
            "Top3 Acc.",
            "Top5 Acc.",
            "Top10 Acc.",
            "Top25 Acc."
        ],
        "data": {
            "num_fns": [],
            "top1": [],
            "top3": [],
            "top5": [],
            "top10": [],
            "top25": [],
        }
    }
    plot_stats = {
        "runs": [],
        "data": {
            "sims": [],
            "confs": []
        }
    }
    for f in files:
        if os.path.exists(f):
            data = {
                "top1": 0,
                "top3": 0,
                "top5": 0,
                "top10": 0,
                "top25": 0
            }
            run = os.path.basename(f).split(".")[0]

            df = pd.read_csv(f)
            total_fns = df['uuid'].nunique()
            matched_fns = df.loc[df["queryfn"] == df["resultfn"]]
            all_matches = df.groupby("uuid")

            # get plot stats
            plot_stats["runs"].append(run)
            plot_stats["data"]["sims"].append(matched_fns["similarity"].to_list())
            plot_stats["data"]["confs"].append(matched_fns["confidence"].to_list())

            # get table stats
            for uuid, matches in all_matches:
                iloc1 = df.index.get_loc(matches.iloc[0].name)
                correct = matches[matches["queryfn"] == matches["resultfn"]]
                if correct.shape[0] != 0:
                    iloc_match = df.index.get_loc(correct.iloc[0].name)
                    match_rank = iloc_match - iloc1 + 1

                    if match_rank == 1:
                        data["top1"] += 1
                    if match_rank <= 3:
                        data["top3"] += 1
                    if match_rank <= 5:
                        data["top5"] += 1
                    if match_rank <= 10:
                        data["top10"] += 1
                    if match_rank <= 25:
                        data["top25"] += 1

            table_stats["runs"].append(run)
            table_stats["data"]["num_fns"].append(total_fns)
            for x in data.keys():
                table_stats["data"][x].append(round(data[x] / total_fns, 3))
        else:
            print(f"Couldn't find {f}")

    plot(plot_stats, table_stats)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Provide files")
    else:
        analyze(sys.argv[1:])
