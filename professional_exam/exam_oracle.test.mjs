// Independent, pre-authored held-out grader. No model output is executed on host.
import test from 'node:test';
import assert from 'node:assert/strict';
import {clamp} from './candidate.mjs';
const cases=[
 ['inside interval',()=>assert.equal(clamp(3,0,5),3)],
 ['lower boundary',()=>assert.equal(clamp(0,0,5),0)],
 ['upper boundary',()=>assert.equal(clamp(5,0,5),5)],
 ['below lower',()=>assert.equal(clamp(-3,0,5),0)],
 ['above upper',()=>assert.equal(clamp(10,0,5),5)],
 ['negative interval',()=>assert.equal(clamp(-3,-5,-2),-3)],
 ['negative lower clipping',()=>assert.equal(clamp(-9,-5,-2),-5)],
 ['negative upper clipping',()=>assert.equal(clamp(0,-5,-2),-2)],
 ['fractional',()=>assert.equal(clamp(1.25,0.5,2.5),1.25)],
 ['fractional clip',()=>assert.equal(clamp(9.25,0.5,2.5),2.5)],
 ['equal limits',()=>assert.equal(clamp(100,4,4),4)],
 ['zero interval',()=>assert.equal(clamp(-0.8,0,0),0)],
 ['invalid first value NaN',()=>assert.throws(()=>clamp(NaN,0,5),TypeError)],
 ['invalid first value Infinity',()=>assert.throws(()=>clamp(Infinity,0,5),TypeError)],
 ['invalid lower -Infinity',()=>assert.throws(()=>clamp(3,-Infinity,5),TypeError)],
 ['invalid upper Infinity',()=>assert.throws(()=>clamp(3,0,Infinity),TypeError)],
 ['invalid string input',()=>assert.throws(()=>clamp("3",0,5),TypeError)],
 ['invalid boolean input',()=>assert.throws(()=>clamp(true,0,5),TypeError)],
 ['invalid null input',()=>assert.throws(()=>clamp(null,0,5),TypeError)],
 ['invalid lower string',()=>assert.throws(()=>clamp(3,"0",5),TypeError)],
 ['inverted bounds',()=>assert.throws(()=>clamp(3,9,1),RangeError)],
 ['inverted negative bounds',()=>assert.throws(()=>clamp(-3,-1,-9),RangeError)],
 ['large finite values',()=>assert.equal(clamp(1e200,0,1e199),1e199)],
 ['small finite values',()=>assert.equal(clamp(1e-12,0,1e-10),1e-12)]
];
for(const [name,fn] of cases)test(name,fn);
