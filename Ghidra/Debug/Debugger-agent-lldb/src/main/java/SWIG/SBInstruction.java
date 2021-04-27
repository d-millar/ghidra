package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public class SBInstruction {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBInstruction(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBInstruction obj) {
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
        lldbJNI.delete_SBInstruction(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBInstruction() {
    this(lldbJNI.new_SBInstruction__SWIG_0(), true);
  }

  public SBInstruction(SBInstruction rhs) {
    this(lldbJNI.new_SBInstruction__SWIG_1(SBInstruction.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBInstruction_IsValid(swigCPtr, this);
  }

  public SBAddress GetAddress() {
    return new SBAddress(lldbJNI.SBInstruction_GetAddress(swigCPtr, this), true);
  }

  public String GetMnemonic(SBTarget target) {
    return lldbJNI.SBInstruction_GetMnemonic(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public String GetOperands(SBTarget target) {
    return lldbJNI.SBInstruction_GetOperands(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public String GetComment(SBTarget target) {
    return lldbJNI.SBInstruction_GetComment(swigCPtr, this, SBTarget.getCPtr(target), target);
  }

  public SBData GetData(SBTarget target) {
    return new SBData(lldbJNI.SBInstruction_GetData(swigCPtr, this, SBTarget.getCPtr(target), target), true);
  }

  public long GetByteSize() {
    return lldbJNI.SBInstruction_GetByteSize(swigCPtr, this);
  }

  public boolean DoesBranch() {
    return lldbJNI.SBInstruction_DoesBranch(swigCPtr, this);
  }

  public boolean HasDelaySlot() {
    return lldbJNI.SBInstruction_HasDelaySlot(swigCPtr, this);
  }

  public boolean CanSetBreakpoint() {
    return lldbJNI.SBInstruction_CanSetBreakpoint(swigCPtr, this);
  }

  public void Print(SBFile out) {
    lldbJNI.SBInstruction_Print__SWIG_0(swigCPtr, this, SBFile.getCPtr(out), out);
  }

  public void Print(SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t BORROWED) {
    lldbJNI.SBInstruction_Print__SWIG_1(swigCPtr, this, SWIGTYPE_p_std__shared_ptrT_lldb_private__File_t.getCPtr(BORROWED));
  }

  public boolean GetDescription(SBStream description) {
    return lldbJNI.SBInstruction_GetDescription(swigCPtr, this, SBStream.getCPtr(description), description);
  }

  public boolean EmulateWithFrame(SBFrame frame, long evaluate_options) {
    return lldbJNI.SBInstruction_EmulateWithFrame(swigCPtr, this, SBFrame.getCPtr(frame), frame, evaluate_options);
  }

  public boolean DumpEmulation(String triple) {
    return lldbJNI.SBInstruction_DumpEmulation(swigCPtr, this, triple);
  }

  public boolean TestEmulation(SBStream output_stream, String test_file) {
    return lldbJNI.SBInstruction_TestEmulation(swigCPtr, this, SBStream.getCPtr(output_stream), output_stream, test_file);
  }

  public String __str__() {
    return lldbJNI.SBInstruction___str__(swigCPtr, this);
  }

}
