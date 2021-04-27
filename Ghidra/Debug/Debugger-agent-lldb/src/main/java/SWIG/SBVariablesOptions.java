package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBVariablesOptions {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBVariablesOptions(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBVariablesOptions obj) {
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
        lldbJNI.delete_SBVariablesOptions(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBVariablesOptions() {
    this(lldbJNI.new_SBVariablesOptions__SWIG_0(), true);
  }

  public SBVariablesOptions(SBVariablesOptions options) {
    this(lldbJNI.new_SBVariablesOptions__SWIG_1(SBVariablesOptions.getCPtr(options), options), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBVariablesOptions_IsValid(swigCPtr, this);
  }

  public boolean GetIncludeArguments() {
    return lldbJNI.SBVariablesOptions_GetIncludeArguments(swigCPtr, this);
  }

  public void SetIncludeArguments(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetIncludeArguments(swigCPtr, this, arg0);
  }

  public boolean GetIncludeRecognizedArguments(SBTarget arg0) {
    return lldbJNI.SBVariablesOptions_GetIncludeRecognizedArguments(swigCPtr, this, SBTarget.getCPtr(arg0), arg0);
  }

  public void SetIncludeRecognizedArguments(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetIncludeRecognizedArguments(swigCPtr, this, arg0);
  }

  public boolean GetIncludeLocals() {
    return lldbJNI.SBVariablesOptions_GetIncludeLocals(swigCPtr, this);
  }

  public void SetIncludeLocals(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetIncludeLocals(swigCPtr, this, arg0);
  }

  public boolean GetIncludeStatics() {
    return lldbJNI.SBVariablesOptions_GetIncludeStatics(swigCPtr, this);
  }

  public void SetIncludeStatics(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetIncludeStatics(swigCPtr, this, arg0);
  }

  public boolean GetInScopeOnly() {
    return lldbJNI.SBVariablesOptions_GetInScopeOnly(swigCPtr, this);
  }

  public void SetInScopeOnly(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetInScopeOnly(swigCPtr, this, arg0);
  }

  public boolean GetIncludeRuntimeSupportValues() {
    return lldbJNI.SBVariablesOptions_GetIncludeRuntimeSupportValues(swigCPtr, this);
  }

  public void SetIncludeRuntimeSupportValues(boolean arg0) {
    lldbJNI.SBVariablesOptions_SetIncludeRuntimeSupportValues(swigCPtr, this, arg0);
  }

  public DynamicValueType GetUseDynamic() {
    return DynamicValueType.swigToEnum(lldbJNI.SBVariablesOptions_GetUseDynamic(swigCPtr, this));
  }

  public void SetUseDynamic(DynamicValueType arg0) {
    lldbJNI.SBVariablesOptions_SetUseDynamic(swigCPtr, this, arg0.swigValue());
  }

}
