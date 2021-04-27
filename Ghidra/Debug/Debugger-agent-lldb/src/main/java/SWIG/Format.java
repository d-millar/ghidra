package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public final class Format {
  public final static Format eFormatDefault = new Format("eFormatDefault", lldbJNI.eFormatDefault_get());
  public final static Format eFormatInvalid = new Format("eFormatInvalid", lldbJNI.eFormatInvalid_get());
  public final static Format eFormatBoolean = new Format("eFormatBoolean");
  public final static Format eFormatBinary = new Format("eFormatBinary");
  public final static Format eFormatBytes = new Format("eFormatBytes");
  public final static Format eFormatBytesWithASCII = new Format("eFormatBytesWithASCII");
  public final static Format eFormatChar = new Format("eFormatChar");
  public final static Format eFormatCharPrintable = new Format("eFormatCharPrintable");
  public final static Format eFormatComplex = new Format("eFormatComplex");
  public final static Format eFormatComplexFloat = new Format("eFormatComplexFloat", lldbJNI.eFormatComplexFloat_get());
  public final static Format eFormatCString = new Format("eFormatCString");
  public final static Format eFormatDecimal = new Format("eFormatDecimal");
  public final static Format eFormatEnum = new Format("eFormatEnum");
  public final static Format eFormatHex = new Format("eFormatHex");
  public final static Format eFormatHexUppercase = new Format("eFormatHexUppercase");
  public final static Format eFormatFloat = new Format("eFormatFloat");
  public final static Format eFormatOctal = new Format("eFormatOctal");
  public final static Format eFormatOSType = new Format("eFormatOSType");
  public final static Format eFormatUnicode16 = new Format("eFormatUnicode16");
  public final static Format eFormatUnicode32 = new Format("eFormatUnicode32");
  public final static Format eFormatUnsigned = new Format("eFormatUnsigned");
  public final static Format eFormatPointer = new Format("eFormatPointer");
  public final static Format eFormatVectorOfChar = new Format("eFormatVectorOfChar");
  public final static Format eFormatVectorOfSInt8 = new Format("eFormatVectorOfSInt8");
  public final static Format eFormatVectorOfUInt8 = new Format("eFormatVectorOfUInt8");
  public final static Format eFormatVectorOfSInt16 = new Format("eFormatVectorOfSInt16");
  public final static Format eFormatVectorOfUInt16 = new Format("eFormatVectorOfUInt16");
  public final static Format eFormatVectorOfSInt32 = new Format("eFormatVectorOfSInt32");
  public final static Format eFormatVectorOfUInt32 = new Format("eFormatVectorOfUInt32");
  public final static Format eFormatVectorOfSInt64 = new Format("eFormatVectorOfSInt64");
  public final static Format eFormatVectorOfUInt64 = new Format("eFormatVectorOfUInt64");
  public final static Format eFormatVectorOfFloat16 = new Format("eFormatVectorOfFloat16");
  public final static Format eFormatVectorOfFloat32 = new Format("eFormatVectorOfFloat32");
  public final static Format eFormatVectorOfFloat64 = new Format("eFormatVectorOfFloat64");
  public final static Format eFormatVectorOfUInt128 = new Format("eFormatVectorOfUInt128");
  public final static Format eFormatComplexInteger = new Format("eFormatComplexInteger");
  public final static Format eFormatCharArray = new Format("eFormatCharArray");
  public final static Format eFormatAddressInfo = new Format("eFormatAddressInfo");
  public final static Format eFormatHexFloat = new Format("eFormatHexFloat");
  public final static Format eFormatInstruction = new Format("eFormatInstruction");
  public final static Format eFormatVoid = new Format("eFormatVoid");
  public final static Format eFormatUnicode8 = new Format("eFormatUnicode8");
  public final static Format kNumFormats = new Format("kNumFormats");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static Format swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + Format.class + " with value " + swigValue);
  }

  private Format(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private Format(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private Format(String swigName, Format swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static Format[] swigValues = { eFormatDefault, eFormatInvalid, eFormatBoolean, eFormatBinary, eFormatBytes, eFormatBytesWithASCII, eFormatChar, eFormatCharPrintable, eFormatComplex, eFormatComplexFloat, eFormatCString, eFormatDecimal, eFormatEnum, eFormatHex, eFormatHexUppercase, eFormatFloat, eFormatOctal, eFormatOSType, eFormatUnicode16, eFormatUnicode32, eFormatUnsigned, eFormatPointer, eFormatVectorOfChar, eFormatVectorOfSInt8, eFormatVectorOfUInt8, eFormatVectorOfSInt16, eFormatVectorOfUInt16, eFormatVectorOfSInt32, eFormatVectorOfUInt32, eFormatVectorOfSInt64, eFormatVectorOfUInt64, eFormatVectorOfFloat16, eFormatVectorOfFloat32, eFormatVectorOfFloat64, eFormatVectorOfUInt128, eFormatComplexInteger, eFormatCharArray, eFormatAddressInfo, eFormatHexFloat, eFormatInstruction, eFormatVoid, eFormatUnicode8, kNumFormats };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

