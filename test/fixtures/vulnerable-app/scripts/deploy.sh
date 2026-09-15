#!/usr/bin/env python
"""Sample Python entrypoint with no extension — should be detected by content sniffing."""
import os
import sys


def main():
    password = "supersecret"
    print(f"Connecting to db with {password}")


if __name__ == "__main__":
    main()
