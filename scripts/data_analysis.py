import sys
import os
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import argparse

import pdb

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

def match_accuracy_plot(df: pd.core.frame.DataFrame) -> bool:
    """ build the match accuracy table """
    # collect results 
    results = []
    runs = df.groupby("run")
    for run, data in runs:
        matched_sim_count = data.loc[data["queryfn"]==data["resultfn"]]["sim_range"].value_counts()

        num_fns = data["uuid"].nunique()
        entry = np.append(
            matched_sim_count.sort_index().values,
            num_fns - matched_sim_count.sum()
        )
        results.append(entry)

    column_labels = [
        "[0.0 - 0.2)",
        "[0.2 - 0.4)",
        "[0.4 - 0.6)",
        "[0.6 - 0.8)",
        "[0.8 - 1.0)",
        "Unmatched"
    ]
    # put results in a df
    table = pd.DataFrame(
        results,
        index=df["run"].unique(),
        columns=column_labels
    )

    # calculate percentages (normalize)
    percents = table.div(table.sum(axis=1),axis=0).mul(100).round(3)

    # plot percentages in a stacked bar graph
    ax = percents.plot(kind="barh", stacked=True)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.05),
        ncol=6,
        frameon=False
    )
    ax.tick_params(left=False, bottom=False)
    ax.spines[['top', 'bottom', 'left', 'right']].set_visible(False)

    for c in ax.containers:
        labels = [f'{w:0.2f}%' if (w := v.get_width()) > 0 else '' for v in c]
        # add annotations
        ax.bar_label(
            c,
            labels=labels,
            label_type='center',
            padding=0.3,
            color='w'
        )
    ax.set_title("Matches by Similarity")
    plt.gcf().set_size_inches(14.5, 5)
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
        #color=colors[0:len(plot_stats["data"]["sims"])],
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
            #color=colors[i],
            s = 5,
            alpha=0.7)
        axs[1].set_xlabel("similarity")
        axs[1].set_ylabel("confidence")
        axs[1].set_title("Correct Match Similarity v. Confidence")

    fig.legend(loc="upper right", bbox_to_anchor=(0.35, 0.90))
    plt.gcf().set_size_inches(10, 6)
    plt.savefig("positive-match-correlation.png")
    plt.clf()

    return True

def top_result(df: pd.core.frame.DataFrame, ns: str) -> bool:
    """ report top1 accuracy based on similarity """

    results = []
    runs = df.groupby("run")
    for run, data in runs:
        total = data["uuid"].nunique()

        # drop after recording all queries, may lose some data
        # inadvertently 
        if ns != "":
            data.drop(
                data[~data["resultfn"].str.startswith(ns)].index,
                inplace=True
            )

        num_top = 0
        num_ties = 0
        num_matched_not_top = 0

        queries = data.groupby("uuid")
        for _, data in queries:
            # if no matches in group, nothing to record, no matches
            if len(data[data["queryfn"] == data["resultfn"]]) == 0:
                continue

            else:
                # get the top result by similarity and keep all ties
                top = data.nlargest(
                    1,
                    "similarity",
                    keep="all")
                # get just matches from the top
                top = top[top["queryfn"] == top["resultfn"]]

                # exactly one match in the top group
                if len(top) == 1:
                    num_top += 1
                # multiple matches tied in the top group
                elif len(top) > 1:
                    num_ties += 1
                # we already know there exists some match
                # but it's not in the top group
                else:
                    num_matched_not_top += 1

        results.append(
            [num_top,
            num_ties,
            num_matched_not_top,
            total - (num_top+num_ties+num_matched_not_top)
            ])

    column_labels = [
        "Top Similarity",
        "Top Similarity w/ Ties",
        "Matched, not top simialarity",
        "Unmatched"
    ]
    # put results in a df
    table = pd.DataFrame(
        results,
        index=df["run"].unique(),
        columns=column_labels
    )

    # calculate percentages (normalize)
    percents = table.div(table.sum(axis=1),axis=0).mul(100).round(3)

    # plot percentages in a stacked bar graph
    ax = percents.plot(kind="barh", stacked=True)
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.05),
        ncol=6,
        frameon=False
    )
    ax.tick_params(left=False, bottom=False)
    ax.spines[['top', 'bottom', 'left', 'right']].set_visible(False)

    for c in ax.containers:
        labels = [f'{w:0.2f}%' if (w := v.get_width()) > 0 else '' for v in c]
        # add annotations
        ax.bar_label(
            c,
            labels=labels,
            label_type='center',
            padding=0.3,
            color='w'
        )
    ax.set_title("Match Accuracy by Top Similarity")
    plt.gcf().set_size_inches(14.5, 5)
    plt.savefig("top-similarity-accuracy.png")

    return True

def calculate_descriptive(df: pd.core.frame.DataFrame) -> bool:
    """ Calculate descriptive statistics

        Geo Mean
    """
    geo_mean = lambda x: np.exp(np.log(x)).mean()
    iqr = lambda x: np.diff(np.percentile(x, [25,75]))
    mad = lambda x: np.median(np.absolute(x - geo_mean(x)))

    outfile = open("descriptive.txt", "w")

    runs = df.groupby("run")
    for run, data in runs:
        outfile.write(f"####### {run} #######\n")
        matched = data[data["queryfn"] == data["resultfn"]]
        unmatched = data[data["queryfn"] != data["resultfn"]]
        # Geo Mean
        outfile.write(f"\tmatched, geomean, similarity:{geo_mean(matched['similarity'])}\n")
        outfile.write(f"\tmatched, geomean, confidence: {geo_mean(matched['confidence'])}\n")
        outfile.write(f"\tunmatched, geomean, similarity: {geo_mean(unmatched['similarity'])}\n")
        outfile.write(f"\tunmatched, geomean, confidence: {geo_mean(unmatched['confidence'])}\n")

        # IQR
        outfile.write(f"\tmatched, iqr, similarity: {iqr(matched['similarity'])}\n")
        outfile.write(f"\tmatched, iqr, confidence: {iqr(matched['confidence'])}\n")
        outfile.write(f"\tunmatched, iqr, similarity: {iqr(unmatched['similarity'])}\n")
        outfile.write(f"\tunmatched, iqr, confidence: {iqr(unmatched['confidence'])}\n")

        # MAD
        outfile.write(f"\tmatched, mad, similarity: {mad(matched['similarity'])}\n")
        outfile.write(f"\tmatched, mad, confidence: {mad(matched['confidence'])}\n")
        outfile.write(f"\tunmatched, mad, similarity: {mad(unmatched['similarity'])}\n")
        outfile.write(f"\tunmatched, mad, confidence: {mad(unmatched['confidence'])}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="perform data analysis on results from bsim")

    # available anlyses
    parser.add_argument(
        "--sim_conf_correlation",
        dest="sim_conf_correlation",
        action="store_true",
        help="perform correlation analysis between similarity and confidence"
    )
    parser.add_argument(
        "--match-accuracy",
        dest="match_accuracy",
        action='store_true',
        help="generate a table of match accuracy by similarity range"
    )
    parser.add_argument(
        "--top-result",
        dest='top_result',
        action="store_true",
        help="generate a table of accuracy in just the top result by similarity"
    )
    parser.add_argument(
        "--descriptive",
        dest="descriptive",
        action="store_true",
        help="calculate a set of descriptive statistics for similarity and \
        confidence"
    )
    parser.add_argument(
        "--all",
        dest="all",
        action="store_true",
        help="perform all available analyses"
    )

    # other arguments
    parser.add_argument(
        "--namespace",
        dest="ns",
        default="",
        help="optional filter by namespace"
    )

    # result files to analyze
    parser.add_argument(
        "files",
        metavar="FILE",
        nargs="+"
    )
    args = parser.parse_args()

    data = prepare_data(args.files)

    if args.match_accuracy or args.all:
        succ = match_accuracy_plot(data)
        if succ:
            print("Generated match accuracy plot")

    if args.sim_conf_correlation or args.all:
        succ = sim_conf_correlation(data)
        if succ:
            print("Generated similarity v. confidence correlations")

    if args.top_result or args.all:
        succ = top_result(data, args.ns)
        if succ:
            print("Generated top result plot")

    if args.descriptive or args.all:
        succ = calculate_descriptive(data)
        if succ:
            print("Generated descriptive statistics")
