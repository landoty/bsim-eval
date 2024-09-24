import sys
import os
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

colors = ["dodgerblue", "forestgreen", "mediumorchid", "black"]

def prepare_data(files: list) -> pd.core.frame.DataFrame:
    """ setup data into a pandas df """
    data = []
    for f in files:
        if os.path.exists(f):
            df = pd.read_csv(f)
            df["similarity"] = df["similarity"].round(5)
            df["sim_range"] = pd.cut(
                                df["similarity"],
                                np.arange(0.0, 1.2, 0.2),
                                labels=np.arange(5)
                            )
            run = os.path.basename(f).split(".")[0]
            df["run"] = run
            data.append(df)

    return pd.concat(data)

def match_accuracy_table(df: pd.core.frame.DataFrame) -> bool:
    """ build the match accuracy table """
    table_stats = {
        "runs": [],
        "row_labels": [
            "[0.0 - 0.2)",
            "[0.2 - 0.4)",
            "[0.4 - 0.6)",
            "[0.6 - 0.8)",
            "[0.8 - 1.0)",
            "# of Matches",
            "# of Functions",
            "Overall Accuracy"
        ],
        "data": {
            "0": [],
            "1": [],
            "2": [],
            "3": [],
            "4": [],
            "num_matches": [],
            "num_fns": [],
            "acc": []
        }
    }
    runs = df.groupby("run")
    for run, data in runs:
        table_stats["runs"].append(run)
        num_fns = data["uuid"].nunique()
        table_stats["data"]["num_fns"].append(num_fns)

        matched_sim_count = data.loc[data["queryfn"]==data["resultfn"]]["sim_range"].value_counts()
        for i in np.arange(5):
            table_stats["data"][str(i)].append(matched_sim_count[i])

        num_matches = matched_sim_count.sum()
        table_stats["data"]["num_matches"].append(num_matches)
        table_stats["data"]["acc"].append(round(num_matches/num_fns, 3))

    plt.table(
        cellText=list(table_stats["data"].values()),
        rowLabels=table_stats["row_labels"],
        colLabels=table_stats["runs"],
        colColours=list(zip(colors, [0.5 for i in range(len(colors))])),
        alpha=0.5,
        loc='center'
    )
    ax = plt.gca()
    ax.get_xaxis().set_visible(False)
    ax.get_yaxis().set_visible(False)
    plt.box(on=None)
    ax.set_title("Correct Matches v. Similarity Scores")
    plt.gcf().subplots_adjust(left=0.3)
    plt.savefig("match-accuracy.png")

    return True

def sim_conf_correlation(df: pd.core.frame.DataFrame) -> bool:
    """ build the correlation plots """
    plot_stats = {
        "runs": [],
        "data": {
            "sims": [],
            "confs": []
        }
    }
    runs = df.groupby("run")
    for run, data in runs:
        plot_stats["runs"].append(run)
        matched_fns = data.loc[data["queryfn"]==data["resultfn"]]
        plot_stats["data"]["sims"].append(matched_fns["similarity"].to_list())
        plot_stats["data"]["confs"].append(matched_fns["confidence"].to_list())

    fig, axs = plt.subplots(1,2,tight_layout=False)
    axs[0].hist(
        plot_stats["data"]["sims"],
        alpha=0.7,
        color=colors[0:len(plot_stats["data"]["sims"])],
        label=plot_stats["runs"],
        bins=10,
        range=(0.0,1.0),
        stacked=True
    )
    axs[0].set_xlabel("similarity")
    axs[0].set_ylabel("# of matches")
    axs[0].set_title("Correct Match Similarity Distr.")

    for i in range(len(plot_stats["data"]["sims"])):
        axs[1].scatter(
            plot_stats["data"]["sims"][i],
            plot_stats["data"]["confs"][i],
            color=colors[i],
            alpha=0.7)
        axs[1].set_xlabel("similarity")
        axs[1].set_ylabel("confidence")
        axs[1].set_title("Correct Match Similarity v. Confidence")

    fig.legend()
    plt.savefig("positive-match-correlation.png")
    plt.clf()

    return True

def analyze(files: list) -> None:
    data = prepare_data(files)

    created_table = match_accuracy_table(data)
    if created_table:
        print("Created match accuracy table")
    else:
        print("Failed to create match accuracy table")

    created_plot = sim_conf_correlation(data)
    if created_plot:
        print("Created sim v. conf correlation plot")
    else:
        print("Failed to create sim v. conf correlation plot")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Provide files")
    else:
        analyze(sys.argv[1:])
