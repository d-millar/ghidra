/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public class ByteArray extends SWIGTYPE_p_void {
  private long swigCPtr; // Minor bodge to work around private variable in parent
  private boolean swigCMemOwn;
  public ByteArray(long cPtr, boolean cMemoryOwn) {
    super(cPtr, cMemoryOwn);
    this.swigCPtr = SWIGTYPE_p_void.getCPtr(this);
    swigCMemOwn = cMemoryOwn;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_ByteArray(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public ByteArray(int nelements) {
    this(lldbJNI.new_ByteArray(nelements), true);
  }

  public byte getitem(int index) {
    return lldbJNI.ByteArray_getitem(swigCPtr, this, index);
  }

  public void setitem(int index, byte value) {
    lldbJNI.ByteArray_setitem(swigCPtr, this, index, value);
  }

  /*
  public SWIGTYPE_p_jbyte cast() {
    long cPtr = lldbJNI.ByteArray_cast(swigCPtr, this);
    return (cPtr == 0) ? null : new SWIGTYPE_p_jbyte(cPtr, false);
  }

  public static ByteArray frompointer(SWIGTYPE_p_jbyte t) {
    long cPtr = lldbJNI.ByteArray_frompointer(SWIGTYPE_p_jbyte.getCPtr(t));
    return (cPtr == 0) ? null : new ByteArray(cPtr, false);
  }
  */

}