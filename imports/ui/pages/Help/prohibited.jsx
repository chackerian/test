import React, { Component } from 'react';
import HelpNav from './nav.jsx';

export default class AboutTerms extends Component {

  render() {
    return(
      <div className="oneDiv">
        <HelpNav />
        <ol className='prohib'>
          <li>weapons; firearms/guns and components; BB/pellet, stun, and spear guns; etc</li>
          <li>ammunition, clips, cartridges, reloading materials, gunpowder, fireworks, explosives</li>
          <li>recalled items; hazardous materials; body parts/fluids; unsanitized bedding/clothing</li>
          <li>prescription drugs, medical devices; controlled substances and related items</li>
          <li>alcohol or tobacco; unpackaged or adulterated food or cosmetics</li>
          <li>child pornography; bestiality; offers or solicitation of illegal prostitution</li>
          <li>pet sales (re-homing with small adoption fee ok), animal parts, stud service</li>
          <li>ivory; endangered, imperiled and/or protected species and any parts thereof</li>
          <li>false, misleading, deceptive, or fraudulent content; bait and switch; keyword spam</li>
          <li>offensive, obscene, defamatory, threatening, or malicious postings or email</li>
          <li>anyone’s personal, identifying, confidential or proprietary information</li>
          <li>food stamps, WIC vouchers, SNAP or WIC goods, governmental assistance</li>
          <li>stolen property, property with serial number removed/altered, burglary tools, etc</li>
          <li>ID cards, licenses, police insignia, government documents, birth certificates, etc</li>
          <li>US military items not demilitarized in accord with Defense Department policy</li>
          <li>counterfeit, replica, or pirated items; tickets or gift cards that restrict transfer</li>
          <li>lottery or raffle tickets, sweepstakes entries, slot machines, gambling items</li>
          <li>spam; miscategorized, overposted, cross-posted, or nonlocal content</li>
          <li>postings or email the primary purpose of which is to drive traffic to a website</li>
          <li>postings or email offering, promoting, or linking to unsolicited products or services</li>
          <li>affiliate marketing; network, or multi-level marketing; pyramid schemes</li>
          <li>any good, service, or content that violates the law or legal rights of others</li>
        </ol>

      </div>
    )
  }
}
