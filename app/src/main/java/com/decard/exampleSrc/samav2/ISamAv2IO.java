/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.decard.exampleSrc.samav2;


/**
 *
 * @author duma
 */
public interface ISamAv2IO {

    /**
     * Send APDU data to SAM device
     * @param apdu
     * @return bytes response
     */
    public byte [] sendApduCommand(byte [] apdu) ;
    
    /**
     * connect (START) to SAM
     * @return 
     */
    public boolean connectCard()  ;
    
    public boolean disconnectCard()  ;

    
    /**
     * get ATR 
     * @return ATR
     */
    public byte[] getATR();
}
