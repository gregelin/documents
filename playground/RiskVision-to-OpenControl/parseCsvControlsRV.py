#!/usr/bin/env python3
#coding: utf8

#
# USAGE:
#   python3 parseCsvControlsRV.py "rv-qna-vam_3-2_IA.csv"

import os, os.path, sys, csv, re, shutil
from collections import OrderedDict
import rtyaml

'''
Read CSV file of controls and output a few columns.
CSV is better than TSV because newlines *within* cell text values
are preserved and quoted in CSV but they are eliminated in TSV.
'''

# Configuration
CONTROL_INDEX = "Control" # Parse the control "AU-04" from row with "Question 26: AU-04.1 Audit Storage Capacity  "
CONTROL_PART_INDEX = "Control Part" # Not apparent in data
COMPONENT_INDEX = "System Element" # Column I
IMPLEMENTATION_STATEMENT_INDEX = "Remediation Plan"
TEST_ARTIFACT_INDEX = "Test Artifact (NIST 800-53A)" # Not applicable
ROW_BREAK = 510 # Lower break number when testing to parse few rows

# Set default opencontrol.yaml configuration
SYSTEM_NAME = "VISTA Data Project"
organization_name =  "Veterans Administration"
ABBREVIATION = "VA"
DESCRIPTION = "The VISTA Data Project is a new data-centric, model-driven approach to VA master data management, interfacing, and security."
REPO_PATH = os.path.join( 'outputs', 'vdp_opencontrol')


# Ensure an argument was passed.
if len(sys.argv) < 2:
  print("Usage:", sys.argv[0], "exported_controls.tsv")
  sys.exit()

# Ensure the passed argument is a file that exists.
fn_tsv = sys.argv[1]
if not os.path.exists(fn_tsv):
  print("Can't find file:", fn_tsv)
  sys.exit()

# Format long text with word wrap and prefix.
def formatImplementation(prefix, text):
  if not prefix[0] == '#':
    text = '\'' + text + '\''
  return textwrap.indent(
    textwrap.fill(text, width=80), prefix, lambda line: True)

# Generate list of potential evidence
def splitArtifacts(text, split_str=None):
  if split_str is not None:
    evidence = text.split(split_str)
  else:
    evidence = text
  return evidence

# Open and parse the /.tsv file and write Low controls to yaml files.
controls = { }
c = 0
with open(fn_tsv, 'r', encoding='utf-8-sig') as csvfile:
  reader = csv.DictReader(csvfile)
  for row in reader:
    c += 1
    if c > ROW_BREAK:
      break

    # Split the control implementation statement on keywords that
    # we recognize that give us separate text for different components
    # and for different "parts" of controls.
    cur_part = None
    cur_component = None
    parts_text = [ ]

    # Get the control implementation narrative
    text = row[IMPLEMENTATION_STATEMENT_INDEX]

    # Get component.
    component = row[COMPONENT_INDEX]

    # Temporary hard-code selection of single component where multiple components are listed
    # So we can more easily show the controls
    for pick_one in ["AWS", "Nessus", "CACE (ELK)", "SonarQube", "ADFS", "GitLab", "CISO"]:
      if pick_one in component:
        component = pick_one

    # When no component identified
    if component == "":
      component = "Missing component"

    print(c, row[CONTROL_INDEX], component)
    # component_parent = row["Database Layer Implementation Statement Source (Postgres SQL)"]

    # The first time we see a (component, control family) pair, create a dict to
    # hold its full name and the controls within it.
    # TODO: Control family should be a look up instead of parsing something
    control_family = row['Control'].split("-")[0] # take off trailing dash
    key = (component, control_family)
    if key not in controls:
      controls[key] = {
        # "name": row['Family'],
        "name": control_family,
        "controls": [],
      }

    # Get control part
    part = row[CONTROL_PART_INDEX]

    # Add this row as a control to its control family.
    # Use an OrderedDict to hold the keys so that when we output
    # it to disk we get the same order on each run.
    def cleanup_text(s):
      # In order for YAML flow-style strings, i.e. "key: >" followed
      # by lines of text, to work, the string must end with a newline,
      # so we'll strip trailing whitespace and then add back a newline
      # to ensure all entries do. The string must also not have spaces
      # immediately before the newline, which are usually mistakes anyway,
      # so we'll just remove those.
      s = s.rstrip() + "\n"
      s = re.sub(r"\s+\n", "\n", s)
      return s

    # Create a stub OpenControl system element to control data object.
    # This data object will eventually be dumped as YAML.
    control = OrderedDict([
      # ('component', component),
      ('control_key', row[CONTROL_INDEX]),
      ('control_family', control_family),
      ('control_key_part', part.strip() if part is not None else None),
      # ('control_name', row['Control Name']),
      ('standard_key', 'NIST SP 800-53 Revision 4'),
      ('covered_by', []),
      ('evidence', splitArtifacts(row[TEST_ARTIFACT_INDEX])),
      # ('security_control_type', row['Security Control Type']),
      ('implementation_status', "Not Implemented"),
      ('narrative', [{"text": cleanup_text(text)}]),
      # ('control_description', cleanup_text(row['Control Description'])),
    ])
    # print("  ", control)
    controls[key]["controls"].append(control)


# Establish empty directory for writing our component files
component_dir = os.path.join('confidential', 'outputs', 'cbp-sams-repo', 'components')
# Try to remove tree; if failed show an error using try...except on screen
try:
    shutil.rmtree(component_dir)
except OSError as e:
    print ("Error: %s - %s." % (e.filename, e.strerror))

# Create a dictionary to track control families associated with a component
# so we can easily generate each component's `component.yaml` file
family_list = {}
# Write out the controls by control family.
for (component, control_family), control_family_data in controls.items():
  # Capture families associated with a control

  # Construct a file name for the component-control family file.
  fn_yaml = os.path.join(
    REPO_PATH,
    'components',
    component.replace(" ", "-") or "Other",
    control_family + "-" + control_family_data["name"].replace(" ", "_") + '.yaml'
  )
  # Append family control file to list
  if component not in family_list:
    family_list[component] = [control_family + "-" + control_family_data["name"].replace(" ", "_") + '.yaml']
  else:
    family_list[component].append(control_family + "-" + control_family_data["name"].replace(" ", "_") + '.yaml')

  # Make directory.
  os.makedirs(os.path.dirname(fn_yaml), exist_ok=True)

  # Write out
  with open(fn_yaml, 'w') as yaml_file:
    doc = OrderedDict([
      ("name", component),
      ("family", control_family_data["name"]),
      ("documentation_complete", False),
      ("schema_version", "3.0.0"),
      ("satisfies", control_family_data["controls"])
    ])
    rtyaml.dump(doc, yaml_file)

# # Write out the system component's component.yaml file
# for (component, control_family), control_family_data  in controls.items():
  fn_component_yaml = os.path.join(
    REPO_PATH,
    'components',
    component.replace(" ","-") or "Other",
    'component.yaml'
  )

  # Write out component.yaml file
  with open(fn_component_yaml, 'w') as yaml_file:
    doc = OrderedDict([
      ("name", component),
      ("documentation_complete", False),
      ("schema_version", "3.0.0"),
      ("satisfies", sorted(family_list[component]))
    ])
    rtyaml.dump(doc, yaml_file)

# Write out the opencontrol.yaml file
def get_new_config(SYSTEM_NAME="MySystem", ORGANIZATION_NAME="MyOrg", ABBREVIATION="", DESCRIPTION="My shiny new IT system"):
    """Create the config file (opencontrol.yaml) data and return values"""

    cfg_str = """schema_version: 1.0.0
name: AgencyApp
metadata:
  authorization_id: ~
  description: Imaginary application for to show faked control narratives.
  organization:
    name: Department of Sobriety
    abbreviation: DOS
  repository: ~
components: []
standards:
- ./standards/NIST-SP-800-53-rev4.yaml
certifications:
- ./certifications/fisma-low-impact.yaml
"""

    # read default opencontrol.yaml into object
    cfg = rtyaml.load(cfg_str)
    # customize values
    cfg["name"] = system_name
    cfg["metadata"]["organization"]["name"] = organization_name
    cfg["metadata"]["description"] = description
    cfg["metadata"]["organization"]["abbreviation"] = abbreviation
    return cfg

cfg = get_new_config(system_name, organization_name, abbreviation, description)
print(cfg["name"])
print("\npreparing system dir: {}".format(system_name))

# Update the list of components
cfg["components"] = list(set(["./components/{}".format(component.replace(" ","-")) for (component, control_family), control_family_data  in controls.items()]))

# create various directories
# os.makedirs(os.path.join(REPO_PATH, "components"))
# os.makedirs(os.path.join(REPO_PATH, "standards"))
# os.makedirs(os.path.join(REPO_PATH, "certifications"))
# os.makedirs(os.path.join(REPO_PATH, "outputs"))

# create opencontrol.yaml config file
with open(os.path.join(REPO_PATH, "opencontrol.yaml"), 'w') as outfile:
    outfile.write(rtyaml.dump(cfg))
    print("wrote file: {}\n".format(os.path.join(REPO_PATH, "opencontrol.yaml")))


# Write out the standards directory
