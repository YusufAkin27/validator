package com.decard.exampleSrc.desfire.ev1.model.command;

import java.io.IOException;

//import android.nfc.tech.IsoDep;

public class DefaultIsoDepWrapper implements IsoDepWrapper {

	private IsoDepWrapper isoDep;
	
	public DefaultIsoDepWrapper(IsoDepWrapper isoDep) {
		this.isoDep = isoDep;
	}
	
	public byte[] transceive(byte[] data) throws IOException {
		return isoDep.transceive(data);
	}
	
	public IsoDepWrapper getIsoDep() {
		return isoDep;
	}
	
	public void connect() throws IOException {
		isoDep.connect();
	}
	
	public void close() throws IOException {
		isoDep.close();
	}
	public boolean isConnected(){
		return true;
	}
}
