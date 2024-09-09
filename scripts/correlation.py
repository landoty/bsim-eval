import matplotlib.pyplot as plt
import sys
import os

def correlate(file: str):
    labels = ["Correctly Matched", "Incorrectly Matched"]
    colors = [("forestgreen", 0.5), ("grey", 0.75)]
    confs = [[], []]
    sims = [[], []]
    fig, axs = plt.subplots(2, 1, tight_layout=False)
    with open(file, "r") as f:
        for l in f.readlines():
            db_fn, match_fn, sim, conf = l.strip().split(",")
            if db_fn == match_fn:
                confs[0].append(float(conf))
                sims[0].append(float(sim))
            else:
                confs[1].append(float(conf))
                sims[1].append(float(sim))

    max_range = max(max(confs[0]), max(confs[1]))
    confs[0] = list(map(lambda x: x / max_range, confs[0]))
    confs[1] = list(map(lambda x: x / max_range, confs[1]))
    bplots = []
    bplots.append(axs[0].boxplot(confs, vert=False, patch_artist=True, tick_labels=labels, showfliers=False))
    bplots.append(axs[1].boxplot(sims, vert=False, patch_artist=True, \
    tick_labels=labels, showfliers=False))

    for bplot in bplots:
        for patch, color in zip(bplot['boxes'], colors):
            patch.set_color(color)

        for median in bplot['medians']:
            median.set_color('black')

    axs[0].set_xlabel("Confidence")
    axs[0].legend([f"Max: {round(max(confs[0]), 3)}", f"Max: {round(max(confs[1]), 3)}"])
    axs[1].set_xlabel("Similarity")
    axs[1].legend([f"Max: {round(max(sims[0]), 3)}", f"Max: {round(max(sims[1]), 3)}"])
    plt.savefig("correlation.png")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("provide a file")
        sys.exit(1)
    if not os.path.exists(sys.argv[1]):
        print("cannot find file")
        sys.exit(1)

    correlate(sys.argv[1])
