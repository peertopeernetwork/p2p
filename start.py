import sys
import p2p


def main():
    if "--open_browser" not in sys.argv:
        sys.argv = (
            [sys.argv[0]]
            + ["--open_browser", "default_browser"]
            + sys.argv[1:]
        )
    p2p.start()


if __name__ == "__main__":
    main()
