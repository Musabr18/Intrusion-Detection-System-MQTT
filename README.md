
  Intrusion Detection System with GUI & MQTT Integration

This project simulates a real-world physical Intrusion Detection System (IDS) using Python, Tkinter for GUI, and MQTT for real-time messaging. Designed for educational use, it allows users to interact with a virtual layout of a building, simulate zone access, and receive instant alerts — just like in real security systems.

  Project Aim
The aim of this project is to demonstrate how intrusion detection systems can be simulated entirely through software. It includes:
- Login system with admin and guest roles
- Real-time zone access simulation
- MQTT-based alert broadcasting
- After-hours detection
- Admin approval workflow
- Export to CSV & PDF

  Key Features
-  Role-Based Access Control (RBAC)  
  Guests and Admins have different access rights

-  GUI Zone Interaction  
  Users click zones on a floor layout to simulate intrusions

-  MQTT Integration  
  Alerts are published to `broker.hivemq.com` on topic `ids/alerts`

-  Live Feed for Admins  
  Admins can subscribe and view alerts in real time

-  Pending Admin Approval  
  Admin requests are stored in `pending_admins.txt` and reviewed by Musab (lead admin)

-  After-Hours Alerting  
  Intrusions outside 8 AM–8 PM are flagged

-  Logging & Reporting  
  Logs saved to text files and exportable to CSV

  How to Run
 Requirements:
- Python 3.9+
- `paho-mqtt`  
  Install via: `pip install paho-mqtt`

 Start the System:
```bash
python intrusion_gui_mqtt.py
```

  Files Included
| File | Description |
|------|-------------|
| `intrusion_gui_mqtt.py` | Main application code |
| `users.txt` | Stores approved users and roles |
| `pending_admins.txt` | Stores admin requests pending approval |
| `intrusion_log.txt` | Records all intrusion events |
| `mqtt_received_log.txt` | (If added) Stores received MQTT messages |
| `house_layout.png` | Background image of the building layout |
| `intrusion_log_report.csv` | Exported CSV report |
| `Appendix_A1_Logbook.docx` | Development logbook |
| `README.md` | Project overview and instructions |

  MQTT Setup
- Broker: `broker.hivemq.com`
- Topic: `ids/alerts`
- Publish Format:
  ```
  [2025-04-17 15:24:08] guest1 accessed Main Door | AFTER HOURS: True
  ```
- Only admins can view the live feed.

  Team Members
| Name       | Role                  |
|------------|-----------------------|
| Musab      | Lead Developer (GUI, MQTT, Logic) |
| Musa       | System Tester         |
| Ifaz       | Debugging, Report Support |
| Yassen     | Documentation & Presenter |
| Gyu-Jin    | UI Designer           |

  Documentation
-  Final Report (Word Doc)
-  UML Diagram
-  Flowchart
-  Logbook

_All located in the `docs/` folder (if uploaded)._

  Project Link
GitHub Repository: https://github.com/Musabr18/Intrusion-Detection-System-MQTT/upload/main


