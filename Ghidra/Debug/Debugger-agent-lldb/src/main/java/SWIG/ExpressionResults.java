package SWIG;


/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


public final class ExpressionResults {
  public final static ExpressionResults eExpressionCompleted = new ExpressionResults("eExpressionCompleted", lldbJNI.eExpressionCompleted_get());
  public final static ExpressionResults eExpressionSetupError = new ExpressionResults("eExpressionSetupError");
  public final static ExpressionResults eExpressionParseError = new ExpressionResults("eExpressionParseError");
  public final static ExpressionResults eExpressionDiscarded = new ExpressionResults("eExpressionDiscarded");
  public final static ExpressionResults eExpressionInterrupted = new ExpressionResults("eExpressionInterrupted");
  public final static ExpressionResults eExpressionHitBreakpoint = new ExpressionResults("eExpressionHitBreakpoint");
  public final static ExpressionResults eExpressionTimedOut = new ExpressionResults("eExpressionTimedOut");
  public final static ExpressionResults eExpressionResultUnavailable = new ExpressionResults("eExpressionResultUnavailable");
  public final static ExpressionResults eExpressionStoppedForDebug = new ExpressionResults("eExpressionStoppedForDebug");
  public final static ExpressionResults eExpressionThreadVanished = new ExpressionResults("eExpressionThreadVanished");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static ExpressionResults swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + ExpressionResults.class + " with value " + swigValue);
  }

  private ExpressionResults(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private ExpressionResults(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private ExpressionResults(String swigName, ExpressionResults swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static ExpressionResults[] swigValues = { eExpressionCompleted, eExpressionSetupError, eExpressionParseError, eExpressionDiscarded, eExpressionInterrupted, eExpressionHitBreakpoint, eExpressionTimedOut, eExpressionResultUnavailable, eExpressionStoppedForDebug, eExpressionThreadVanished };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

