using System;
using System.Reflection;
using System.Linq;

var asm = Assembly.LoadFrom(@"J:\Nuget\Packages\sipsorcery\10.0.12\lib\net8.0\SIPSorcery.dll");
string[] typeNames = new[] {
    "SIPSorcery.SIP.SIPURI",
    "SIPSorcery.SIP.SIPEndPoint", 
    "SIPSorcery.SIP.SIPResponseStatusCodesEnum",
    "SIPSorcery.SIP.SIPViaHeader",
    "SIPSorcery.SIP.SIPContactHeader",
    "SIPSorcery.SIP.SIPFromHeader",
    "SIPSorcery.SIP.SIPToHeader",
    "SIPSorcery.SIP.SIPAuthenticationHeader",
    "SIPSorcery.SIP.SIPDialogue",
    "SIPSorcery.SIP.SIPTransport"
};
foreach (var tn in typeNames) {
    var t = asm.GetType(tn);
    if (t == null) { Console.WriteLine("NOT FOUND: " + tn); continue; }
    Console.WriteLine("\n=== " + tn + " ===");
    foreach (var c in t.GetConstructors(BindingFlags.Public|BindingFlags.Instance))
        Console.WriteLine("  .ctor(" + string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name+" "+p.Name)) + ")");
    foreach (var p in t.GetProperties(BindingFlags.Public|BindingFlags.Instance).Take(25))
        Console.WriteLine("  ."+p.Name+": "+p.PropertyType.Name);
    foreach (var m in t.GetMethods(BindingFlags.Public|BindingFlags.Static|BindingFlags.DeclaredOnly).Take(15))
        Console.WriteLine("  static ."+m.Name+"("+string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name+" "+p.Name))+"): "+m.ReturnType.Name);
}
