package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBLanguageRuntime {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBLanguageRuntime(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBLanguageRuntime obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBLanguageRuntime(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public static LanguageType GetLanguageTypeFromString(String string) {
    return LanguageType.swigToEnum(lldbJNI.SBLanguageRuntime_GetLanguageTypeFromString(string));
  }

  public static String GetNameForLanguageType(LanguageType language) {
    return lldbJNI.SBLanguageRuntime_GetNameForLanguageType(language.swigValue());
  }

  public SBLanguageRuntime() {
    this(lldbJNI.new_SBLanguageRuntime(), true);
  }

}
