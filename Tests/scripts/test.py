import sys
import pyminizip
import zipfile


def main(args):
    pyminizip.compress_multiple(['file1.log', 'file2.log'], [], args[0], 'Password1!', zipfile.ZIP_DEFLATED)


if __name__ == '__main__':
    main(sys.argv[1:])