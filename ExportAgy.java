// Static, targeted decompilation using recovered Go function boundaries.
//@category Agy
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class ExportAgy extends GhidraScript {
    private String safe(String n) { return n.replaceAll("[^A-Za-z0-9_$]", "_"); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path root = Paths.get(args[0]);
        List<String[]> selected = new ArrayList<>();
        int labels = 0;
        for (String line : Files.readAllLines(root.resolve("recovered/functions.tsv"))) {
            if (line.startsWith("address\t")) continue;
            String[] r = line.split("\t");
            Address address = toAddr(Long.decode(r[0]));
            try { createLabel(address, safe(r[3]), true, SourceType.IMPORTED); labels++; }
            catch (Exception e) { /* Preserve existing import labels. */ }
            String n = r[3];
            boolean choose = n.startsWith("main.") ||
                n.startsWith("google3/third_party/jetski/cli/entrypoints/") ||
                n.startsWith("google3/third_party/jetski/cli/printmode/") ||
                n.startsWith("google3/third_party/jetski/cli/modelresolver/") ||
                n.startsWith("google3/third_party/jetski/cli/remotecontrol/");
            if (args.length > 1) choose = n.matches(args[1]);
            if (choose) selected.add(r);
        }
        println("Recovered labels: " + labels + "; selected functions: " + selected.size());
        for (String[] r : selected) {
            Address start = toAddr(Long.decode(r[0]));
            Address end = toAddr(Long.decode(r[1])-1);
            AddressSet body = new AddressSet(start, end);
            new DisassembleCommand(start, body, true).applyTo(currentProgram, monitor);
            Function f = currentProgram.getFunctionManager().getFunctionAt(start);
            if (f == null) f = currentProgram.getFunctionManager().createFunction(
                safe(r[3]), start, body, SourceType.IMPORTED);
            f.setComment("Recovered Go name: " + r[3]);
        }
        Path out = root.resolve(args.length > 2 ? args[2] : "recovered/decompiled");
        Files.createDirectories(out);
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.openProgram(currentProgram);
        int good = 0;
        try (BufferedWriter index = Files.newBufferedWriter(out.resolve("index.tsv"))) {
            index.write("address\tname\tfile\tstatus\n");
            for (String[] r : selected) {
                monitor.checkCancelled();
                Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(Long.decode(r[0])));
                DecompileResults result = decompiler.decompileFunction(f, 30, monitor);
                String file = r[0]+"_"+safe(r[3]);
                if (file.length() > 190) file = file.substring(0,190);
                file += ".c";
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = "/* Recovered Go function: "+r[3]+"\n   Address: "+r[0]+
                        "\n   Ghidra pseudocode; types/ABI may be inaccurate. */\n\n"+
                        result.getDecompiledFunction().getC();
                    Files.writeString(out.resolve(file), code);
                    good++;
                    index.write(r[0]+"\t"+r[3]+"\t"+file+"\tOK\n");
                } else {
                    index.write(r[0]+"\t"+r[3]+"\t\t"+result.getErrorMessage().replace('\n',' ') +"\n");
                }
                if (good % 25 == 0) println("Decompiled " + good + ": " + r[3]);
                index.flush();
            }
        }
        decompiler.dispose();
        println("EXPORT COMPLETE: " + good + "/" + selected.size());
    }
}
