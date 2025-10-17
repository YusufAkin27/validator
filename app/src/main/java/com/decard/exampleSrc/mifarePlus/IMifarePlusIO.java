/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.mifarePlus;


/**

 @author duma
 */
public interface IMifarePlusIO {

    public byte[] sendApduCommand(byte[] apdu) ;

    public byte[] sendApduControlCommand(byte[] apdu);

   //public byte [] sendFelicaApduCommand(byte [] apdu);

}
