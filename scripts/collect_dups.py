import pandas as pd
import matplotlib.pyplot as plt
import xml.etree.ElementTree as XMLTree
import argparse
import sys, os

def collect(sig_paths: list, fname: str = "") -> dict:
    dups = {}
    for sig in sig_paths:
        if os.path.exists(sig):
            try:
                tree = XMLTree.parse(sig)
            except Exception as e:
                print(f"Not XML: {sig}")
                continue

            sig = os.path.basename(os.path.normpath(sig))
            dups[sig] = []
            execlist = tree.getroot()[0]

            if "sigdup" not in execlist[1].attrib:
                execlist = tree.getroot()[1]

            for elem in execlist[1:]:
                if "sigdup" in elem.attrib:
                    if fname != "" and not elem.attrib["name"].startswith(fname):
                        continue
                    dups[sig].append(int(elem.attrib["sigdup"], 16))
        else:
            print(f"Couldn't find {sig}. Skipping")

    return dups

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="collect signature duplicates statistics"
    )
    parser.add_argument(
        "signatures",
        metavar="S",
        nargs="+",
        help="space delimited list of signature files"
    )
    parser.add_argument(
        "--name",
        dest="name",
        default="",
        help="Optional argument to filter by name"
    )
    args = parser.parse_args()
    # collect stats
    dups = collect(args.signatures, args.name)
    df = pd.DataFrame(
            dict([
            (key, pd.Series(value))
            for key, value in
            dups.items()])
        )
    # plot and save
    df = df.describe()
    fig, ax = plt.subplots()
    fig.patch.set_visible(False)
    ax.axis('off')
    ax.axis('tight')
    ax.table(
        cellText=df.values,
        rowLabels=df.index.to_list(),
        colLabels=df.columns,
        loc='center',
    )
    plt.savefig("duplicate_signatures.png", dpi=400)
