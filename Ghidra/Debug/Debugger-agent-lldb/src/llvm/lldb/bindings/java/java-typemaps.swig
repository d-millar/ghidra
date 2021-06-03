%include <typemaps.i>

%include <carrays.i>

%typemap(javabase) ByteArray "SWIGTYPE_p_void"
%typemap(javabody) ByteArray %{
  private long swigCPtr; // Minor bodge to work around private variable in parent
  private boolean swigCMemOwn;
  public $javaclassname(long cPtr, boolean cMemoryOwn) {
    super(cPtr, cMemoryOwn);
    this.swigCPtr = SWIGTYPE_p_void.getCPtr(this);
    swigCMemOwn = cMemoryOwn;
  }
%}

%array_class(jbyte, ByteArray);

/*
%typemap(in,numinputs=0) JNIEnv *env "$1 = jenv;"

%javamethodmodifiers arr2voidb "private";
%javamethodmodifiers arr2voidi "private";
%javamethodmodifiers freearrb "private";
%javamethodmodifiers freearri "private";
%inline %{

jlong arr2voidb(JNIEnv *jenv, jbyteArray arr) {
  void *ptr = jenv->GetByteArrayElements(arr, NULL);
  return (intptr_t)ptr;
}

void freearrb(JNIEnv *jenv, jbyteArray arr, jlong map) {
  jbyte *ptr = 0;
  ptr = *(jbyte **)&map;
  jenv->ReleaseByteArrayElements(arr, ptr, JNI_ABORT);
}

jlong arr2voidi(JNIEnv *jenv, jintArray arr) {
  void *ptr = jenv->GetIntArrayElements(arr, NULL);
  return (intptr_t)ptr;
}

void freearri(JNIEnv *jenv, jintArray arr, jlong map) {
  jint *ptr = 0;
  ptr = *(jint **)&map;
  jenv->ReleaseIntArrayElements(arr, ptr, JNI_ABORT);
}
%}


%pragma(java) modulecode=%{
  private static long arrPtr(Object o) {
    if (o instanceof byte[]) {
      return arr2voidb((byte[])o);
    }
    if (o instanceof int[]) {
      return arr2voidi((int[])o);
    }
    throw new IllegalArgumentException();
  }

  private static void freeArrPtr(Object o, long addr) {
    if (o instanceof byte[]) {
      freearrb((byte[])o, addr);
      return;
    }
    if (o instanceof int[]) {
      freearri((int[])o, addr);
      return;
    }
    throw new IllegalArgumentException();
  }
%}

%typemap(jstype) void *arr "Object"
%typemap(javain,pre="    long tmp$javainput = arrPtr($javainput);",post="      freeArrPtr($javainput, tmp$javainput);") void *arr "tmp$javainput"

*/