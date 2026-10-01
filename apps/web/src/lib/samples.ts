export const BASIC_SAMPLE = [
  "Received: from relay.sender.example (relay.sender.example [192.0.2.25])",
  " by mx.recipient.example with ESMTPS id route-002",
  " for <bob@recipient.example>; Thu, 01 Oct 2026 12:00:00 +0000",
  "Received: from laptop.local ([192.168.1.10])",
  " by relay.sender.example with ESMTP id route-001;",
  " Thu, 01 Oct 2026 11:59:43 +0000",
  "Authentication-Results: mx.recipient.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example",
  "From: Alice <alice@sender.example>",
  "To: Bob <bob@recipient.example>",
  "Subject: 项目进度",
  "Message-ID: <sample-001@sender.example>",
  "",
  "Synthetic example.",
].join("\r\n");

export const LOOP_SAMPLE = [
  "Received: from relay-b.example by relay-a.example with ESMTP; Thu, 01 Oct 2026 12:00:10 +0000",
  "Received: from relay-a.example by relay-b.example with ESMTP; Thu, 01 Oct 2026 12:00:20 +0000",
  "Authentication-Results: mx.recipient.example; spf=fail smtp.mailfrom=sender.example; dkim=none",
  "From: investigator@sender.example",
  "Subject: 可疑回返与时间异常",
  "",
  "Synthetic example.",
].join("\r\n");
