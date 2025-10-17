package com.decard.exampleSrc.desfire.ev1.model.command;

import java.io.IOException;

public interface IsoDepWrapper {

	byte[] transceive(byte[] data) throws IOException;
	boolean isConnected();

	public void connect() throws IOException;
	public void close() throws IOException;
}
