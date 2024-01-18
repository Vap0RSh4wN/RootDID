// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Verify_VC_predicate {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2 = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1 = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2 = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 2287578126608721110042162179343638168513320293862664182537754949753282240577;
    uint256 constant deltax2 = 4663584832844700209121777197801899772251304762653108703947513330660882794869;
    uint256 constant deltay1 = 2613710178462482141682182003695324658527905710623697971365827647329113583856;
    uint256 constant deltay2 = 17538044842554009519501627618045303440200451549933205931522502155255385141637;

    uint256 constant IC0x = 5914975106674973133654408525290552162634188805178980141973125142143468155762;
    uint256 constant IC0y = 4216503689290749240173986766805545144581789600484212516186063095176146057537;

    uint256 constant IC1x = 14415255608252101936380328020123214505084345493507119920927798953161751204502;
    uint256 constant IC1y = 2557309925908365090891244212887575994473382891452418937653511078322904325410;

    uint256 constant IC2x = 17353202669418058584140174777975760770959655272377685436753549952109863146855;
    uint256 constant IC2y = 14030083599526931491148405100442317101855707199885457900533634692542207470030;

    uint256 constant IC3x = 11680625863216656671424161379322710730342499659858032636820722525247263434785;
    uint256 constant IC3y = 12330485894186916891983049594529502901631105303673347269086524073858763613977;

    uint256 constant IC4x = 17033299455007412692666091585527421822569800675585603453604490161277290737351;
    uint256 constant IC4y = 16798533783125216396381696226278123245723682133402883236528894170688181846201;

    uint256 constant IC5x = 1416129319351025324888047511992186614620417109090402069209256066902252139758;
    uint256 constant IC5y = 12892728933059066427764367806378432752338826027105697194240848426791807182000;

    uint256 constant IC6x = 17191776153345459310302051960424870967085183702848625085409157103271701620533;
    uint256 constant IC6y = 515966582483896888258109388395434321681557381480099648505244200637750870293;

    uint256 constant IC7x = 7530737847859757440289295291878509639605506922518758442790631673766274049301;
    uint256 constant IC7y = 12520542307730920481349158454918972352045512491034690410440080278537590985089;

    uint256 constant IC8x = 4371952767695780472785902941927992296681799662986102463876977335537038076043;
    uint256 constant IC8y = 8300228055939130316986801725385692156423174050895387429320602466684681140563;

    uint256 constant IC9x = 20309695472910413360000894789536716412573375130710711648201543039210837875822;
    uint256 constant IC9y = 12240358235952166297344428819728782399204945466482532654114482347061236399224;

    uint256 constant IC10x = 6017014591106268329208197829098246749058598420151125753848454335658082792965;
    uint256 constant IC10y = 3154712644430468287142593426148059746370906471210036837203979528901328925728;

    uint256 constant IC11x = 14181706579309150472908465370471140504061372374270045591606877814825446825227;
    uint256 constant IC11y = 18513715508247602321889067609986888397416654947510339800586409727572837224969;

    uint256 constant IC12x = 4668664627011384264127909271245226831451806573089336075231057778080103458147;
    uint256 constant IC12y = 20563383807419129536647907018319638373282140579374112429376279770580350054196;

    uint256 constant IC13x = 17075506390034591835623532083985181386031816243942836526933287696634835133918;
    uint256 constant IC13y = 15794015908695609340169784495900524414024346620954429306851231775238615256841;

    uint256 constant IC14x = 9689593693408057897822329612834286363346826216300320176442703487668473162886;
    uint256 constant IC14y = 6210812628094852482573444222461972130716540611475062409204781984548075030597;

    uint256 constant IC15x = 2596473507806519202327914803591438643696885829663482133785824131402283979352;
    uint256 constant IC15y = 9761676880925570397147855768953001753735628946627860823426691633087621188130;

    uint256 constant IC16x = 9720554245563659544761980566495538054266036957812959312247629918645720474410;
    uint256 constant IC16y = 19150485580737461441043147695886163978431868408122748431811351424388793782079;

    uint256 constant IC17x = 6073388020288530233323886409514507092170710829538683445802198946738741439148;
    uint256 constant IC17y = 17694245613299901836956136237001042889666405372159000582062228816547751984143;

    uint256 constant IC18x = 6011680120845935271189122869063173402682838851637783725432254405752238652250;
    uint256 constant IC18y = 10033334502586594408886313769182779290191610227771119820185477944893111691904;

    uint256 constant IC19x = 18129406622773282483310062962663977105830805077694905007001209016924566919962;
    uint256 constant IC19y = 3313142312413642433189142657711812412808282635805878945096952671234872352813;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[19] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))

                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))

                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))

                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))

                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))

                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            checkField(calldataload(add(_pubSignals, 416)))

            checkField(calldataload(add(_pubSignals, 448)))

            checkField(calldataload(add(_pubSignals, 480)))

            checkField(calldataload(add(_pubSignals, 512)))

            checkField(calldataload(add(_pubSignals, 544)))

            checkField(calldataload(add(_pubSignals, 576)))

            checkField(calldataload(add(_pubSignals, 608)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
