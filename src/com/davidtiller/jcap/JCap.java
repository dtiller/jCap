package com.davidtiller.jcap;

/*
	jCap - Capture network traffic without promiscuous mode permissions
	and write the traffic to a file.
	The output files can be read by the Wireshark utility text2cap 
	and then analyzed by wireshark.

    Copyright (C) 2018  David E. Tiller

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

public class JCap {

	static int listenPort = 8080;
	static int destPort = 80;
	static int maxSegment = 32768;
	static String destHost = null;
	static boolean debug = false;
	static final PrintStream log = System.out;

	public static void main(String[] args) {
		copyright();
		
		if (args.length % 2 != 0) {
			usage("Odd number of args.", 1);
		}

		for (int i = 0; i < args.length; i += 2) {
			if ("--server-port".equals(args[i])) {
				listenPort = Integer.parseInt(args[i + 1]);
			} else if ("--dest-port".equals(args[i])) {
				destPort = Integer.parseInt(args[i + 1]);
			} else if ("--dest-host".equals(args[i])) {
				destHost = args[i + 1];
			} else if ("--debug".equals(args[i])) {
				debug = Boolean.parseBoolean(args[i + 1]);
			} else if ("--max-segment".equals(args[i])) {
				maxSegment = Integer.parseInt(args[i + 1]);
			} else {
				usage("Unknown argument " + args[i], 2);
			}
		}
		
		if (destHost == null) {
			usage("--dest-host must be specified", 3);
		}
		
		System.out.println("Process output files with text2pcap:");
		System.out.println("\ttext2pcap -n -t %T. -D -T " + listenPort + "," + destPort + " infile outfile.pcap");

		try {
			ServerSocketChannel ssc = ServerSocketChannel.open();
			ServerSocket ss = ssc.socket();
			ss.bind(new InetSocketAddress(listenPort), 20);

			while (true) {
				debug("accepting");
				new Thread(new ConnectionProcessor(ssc.accept())).start();
				debug("accepted");
			}

		} catch (Exception e) {
			System.err.println("Exception: " + e);
		}
	}

	static void debug(Object o) {
		if (debug)
			log.println(o);
	}

	static class ConnectionProcessor implements Runnable {
		private SocketChannel inSocketChannel;
		private InetSocketAddress sourceSocketAddr;
		private String filename;
		private long byteCount = 0;

		public ConnectionProcessor(SocketChannel s) {
			inSocketChannel = s;
			sourceSocketAddr = (InetSocketAddress) s.socket()
					.getRemoteSocketAddress();
			filename = getFilename();
		}

		@Override
		public void run() {
			System.out.println("Opening file " + filename);
			try {
				PrintWriter pw = new PrintWriter(new BufferedWriter(
						new FileWriter(filename)));

				writeHeader(pw, inSocketChannel);

				inSocketChannel.configureBlocking(false);

				SocketChannel outSocketChannel = SocketChannel
						.open(new InetSocketAddress(destHost, destPort));
				outSocketChannel.configureBlocking(false);

				Selector sel = Selector.open();
				SelectionKey inSocketKey = inSocketChannel.register(sel,
						SelectionKey.OP_READ);
				SelectionKey outSocketKey = outSocketChannel.register(sel,
						SelectionKey.OP_READ);

				while (true) {
					debug("selecting");
					debug("keys.size: " + sel.keys().size());
					int keyCount = sel.select();
					debug("keycount: " + keyCount);
					if (keyCount > 0) {
						Set<SelectionKey> keys = sel.selectedKeys();
						Iterator<SelectionKey> i = keys.iterator();
						while (i.hasNext()) {
							SelectionKey key = i.next();
							i.remove();

							boolean closed = false;
							if (key.equals(inSocketKey)) {
								debug("insocket ready for read");
								closed = processData(inSocketChannel,
										outSocketChannel, pw, true);
							} else if (key.equals(outSocketKey)) {
								debug("outsocket ready for read");
								closed = processData(outSocketChannel,
										inSocketChannel, pw, false);
							} else {
								System.err.println("Unknown selectionKey: "
										+ key);
							}

							if (closed) {
								debug("Gone!");
								System.out.println("Closing file " + filename + ", " + byteCount + " data bytes written.");
								return;
							}
						}
					} else {
						debug("unexpected value from select: " + keyCount);
						System.exit(4);
					}
				}
			} catch (IOException ioe) {
				System.err.println("IOException:" + ioe);
			}
		}

		private boolean processData(SocketChannel read, SocketChannel write,
				PrintWriter pw, boolean inbound) {
			int count;
			ByteBuffer bb = ByteBuffer.allocateDirect(maxSegment);
			try {
				do {
					debug("trying to read");
					count = read.read(bb);
					debug("read " + count);
					if (count == -1) {
						debug("Closing");
						read.close();
						write.close();
						pw.close();
						return true;
					} else if (count > 0) {
						bb.flip();
						writeFileData(pw, bb, inbound);
						bb.rewind();
						write.write(bb);
						bb.clear();
						byteCount += count;
					}
				} while (count == maxSegment);

				return false;
			} catch (IOException ioe) {
				try {
					read.close();
					pw.close();
					write.close();
				} catch (IOException ioe1) {
					debug("Unable to close channels: " + ioe1);
				}
				return false;
			}
		}

		private String getFilename() {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmssSSS");
			String timestamp = sdf.format(new Date());

			String filename = timestamp + "_" + sourceSocketAddr.getPort();

			return filename;

		}

		private void writeHeader(PrintWriter pw, SocketChannel sc)
				throws IOException {
			InetSocketAddress sa = (InetSocketAddress) sc.socket()
					.getRemoteSocketAddress();
			String header = "# Connection from " + sa.getHostName() + ":"
					+ sa.getPort() + " to " + destHost + ":" + destPort
					+ " at " + new Date();
			pw.println(header);
		}

		private void writeFileData(PrintWriter pw, ByteBuffer bb,
				boolean inbound) {
			// This is the same as %H:%M:%S and can have millisecs
			SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

			if (inbound) {
				pw.println("I");
			} else {
				pw.println("O");
			}

			pw.print(sdf.format(new Date()));
			try {
				hexDump(pw, bb);
			} catch (IOException ioe) {
				System.err.println("Exception writing data: " + ioe);
			}
		}

		private void hexDump(PrintWriter pw, ByteBuffer bb) throws IOException {
			int stride = 128;
			long offset = 0;

			while (bb.hasRemaining()) {
				byte b = bb.get();
				if (offset % stride == 0) {
					pw.println();
					pw.print(String.format("%05x ", offset));
				}

				pw.print((String.format("%02x ", b)));
				offset++;
			}

			pw.println();
			pw.println(String.format("%05x ", offset));
			pw.println();
		}
	}
	
	private static void usage(String msg, int exitCode) {
		System.err.println(msg);
		System.err.println("\nUsage:");
		System.err.println("jCap --dest-host <host-or-ip>");
		System.err.println("\t[--dest-port <port> (default 80)]");
		System.err.println("\t[--listen-port <port> (default 8080)]");
		System.err.println("\t[--debug <true|false>]");
		System.err.println("\t[--max-segment <seg-size> (default 32768)]");
		System.exit(exitCode);
	}
	
	private static void copyright() {
		System.out.println("jCap - Copyright (C) 2018  David E. Tiller");
		System.out.println("This program comes with ABSOLUTELY NO WARRANTY; for details see");
		System.out.println("https://www.gnu.org/licenses/gpl-3.0.html");
		System.out.println("This is free software, and you are welcome to redistribute it under");
		System.out.println("certain conditions; for details see https://www.gnu.org/licenses/gpl-3.0.html");
		System.out.println();
	}

}
