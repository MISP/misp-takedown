from asciimatics.widgets import Frame, TextBox, Layout, Label, Divider, Text, \
    CheckBox, RadioButtons, Button, PopUpDialog
from asciimatics.scene import Scene
from asciimatics.screen import Screen, Canvas
from asciimatics.exceptions import ResizeScreenError, NextScene, StopApplication
from asciimatics.event import KeyboardEvent, MouseEvent
import sys
from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json
import collections
#import ssl
from string import Template
import urllib
import urllib2
from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError
from rtkit import set_logging
import logging
import asciiconfig as cfg
sys.path.append(cfg.urlabuse_path)
import url_abuse as urlabuse
from defang import defang
from defang import refang
from rtkit.resource import RTResource
from rtkit.authenticators import CookieAuthenticator
from rtkit.errors import RTResourceError
from rtkit import set_logging
import logging
import sphinxapi
import contextlib
import multiprocessing
import time
import magic

class Consumer(multiprocessing.Process):
    
    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        proc_name = self.name
        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                # Poison pill means shutdown
                self.task_queue.task_done()
                break
            answer = next_task()
            self.task_queue.task_done()
            self.result_queue.put(answer)
        return


class Task(object):
    def __init__(self, i, t, u, o, oc):
        self.i = i
        self.t = t
        self.u = u
        self.o = o
        self.oc = oc
    def __call__(self):
        time.sleep(1)
        return check_url_create_investigation(self.i, self.t, self.u, self.o, onlinecheck = self.oc) 
    def __str__(self):
        return '%s: %s' % (self.i, self.u)

class DummyFile(object):
    def write(self, x): pass

@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    sys.stdout = DummyFile()
    yield
    sys.stdout = save_stdout

excludelist = cfg.excludelist
rt_url = cfg.rt_url
rt_user = cfg.rt_user
rt_pass = cfg.rt_pass
sphinx_server = cfg.sphinx_server
sphinx_port = cfg.sphinx_port
debug = cfg.debug
override_email = cfg.override_email
ua = cfg.ua
min_size = cfg.min_size
log_init = cfg.log_init
logsize = cfg.logsize  

def log(buffer, screen, l, content, x, y):
    global log_init
    global logsize
    content = " " + content
    offset_vert = 4
    y = y - (logsize + offset_vert)
    line_length = screen.width - 20
    if log_init is False:
        for i in range(1, logsize):
            screen.print_at(" "*line_length, x, y+i)
            l.reset()
        screen.refresh()
        log_init = True
    buffer.append(content)
    message = ""
    for element in buffer:
        clean_msg = (line_length - len(element)) * " " 
        message = element + clean_msg
        screen.print_at(message, x, y)
        y += 1
        l.reset()
    screen.refresh()
         

def is_online(resource):
    try:
        global ua
        global min_size
        request = urllib2.Request(resource)
        request.add_header('User-agent', ua)
        response = urllib2.urlopen(request, timeout=60)
        size = len(response.read())
        with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
            mimetype = m.id_buffer(response.read())
        if int(size) > min_size and 'html' not in mimetype:
            return True, size
        else:
            return False, size
    except Exception as e:
        return False, -1

def is_ticket_open(id):
    status = False
    global rt_url
    global rt_user
    global rt_pass
    resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)
    try:
        ticket="ticket/%s" % id
        response = resource.get(path=ticket)
        for r in response.parsed:
            l = { a:b for a,b in r }
            ticket_status = l["Status"]
            if ticket_status == "open" or ticket_status == "new":
                status = id
    except:
        return False
    return status

def open_tickets_for_url(url):
    global sphinx_server
    global sphinx_port
    # Sphinx
    client = sphinxapi.SphinxClient()
    client.SetServer(sphinx_server, sphinx_port)
    client.SetMatchMode(2)
    q   = "\"%s\"" % url
    res = 0
    tickets = []
    result = client.Query(q)
    for match in result['matches']:
        res = is_ticket_open(match['id'])
    return res

def check_url_create_investigation(incident, template, url, override, onlinecheck):
    mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
    template = os.path.join(mypath, template)
    global ua
    global min_size
    global override_email
    global event_tag
    # RT
    set_logging('error')
    logger = logging.getLogger('rtkit')
    resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)
    open_tickets = open_tickets_for_url(url)
    if open_tickets > 0:
        return "URL %s was already handled in ticket %s" % (url, open_tickets)
    if onlinecheck is True:
        online,size = is_online(url)
    	if not online:
            return "URL %s is offline (size: %s)" % (url, size) 
    with nostdout():
        emails, text, asn = urlabuse.run_lookup(url)
    text = defang(urllib.quote(text))
    d={ 'details' : text }

    try:
        f = open(template)
        subject = f.readline().rstrip()
    	templatecontent = Template( f.read() )
    	body = templatecontent.substitute(d)
    except:
	    print "Couldn't open template file (%s)" % template
	    sys.exit(1)
    f.close()
    if event_tag == "tlp:green":
        subject = "[TLP:GREEN] " + subject
    # Override emails destinations for test
    if override is True:
        emails = override_email

    asn_out=[]
    for x in asn:
        asn_out.append(",".join(x))
    asn_out = "|".join(asn_out)
    subject = "%s (%s)" % (subject, asn_out)
    content = {
	    'content': {
	        'queue': 5,
	        'requestor': emails,
	        'subject': urllib.quote(subject),
	        'text': body,
	    }
    }

    if debug:
	    sys.exit(42)

    try:
	    response = resource.post(path='ticket/new', payload=content,)
	    logger.info(response.parsed)
	    for t in response.parsed:
	        ticketid = t[0][1]
    except RTResourceError as e:
	    logger.error(e.response.status_int)
	    logger.error(e.response.status)
	    logger.error(e.response.parsed)

    #update ticket link
    content = {
	    'content': {
	        'memberof': incident,
	    }
    }
    try:
        ticketpath="%s/links" % ticketid
        response = resource.post(path=ticketpath, payload=content,)
        logger.info(response.parsed)
        return "Investigation created for URL %s" % (url)
    except RTResourceError as e:
	    logger.error(e.response.status_int)
	    logger.error(e.response.status)
	    logger.error(e.repoinse.parsed)


def create_ticket(mispid, subject):
    set_logging('error')
    logger = logging.getLogger('rtkit')
    resource = RTResource(rt_url, rt_user, rt_pass, CookieAuthenticator)

    emails = "sascha.rommelfangen@circl.lu"

    subject = "%s - takedown" % (subject)
    body    = "Automatically imported via MISP # %s" % (mispid)
    content = {
        'content': {
            'queue': 3,
            'requestor': emails,
            'subject': urllib.quote(subject),
            'text': body,
        }
    }

    try:
        response = resource.post(path='ticket/new', payload=content,)
        logger.info(response.parsed)
        for t in response.parsed:
            ticketid = t[0][1]
        return ticketid.replace('ticket/', '')
    except RTResourceError as e:
        logger.error(e.response.status_int)
        logger.error(e.response.status)
        logger.error(e.response.parsed)


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

urllist = []
ticket_id = 0
event_name = ""
event_tag = ""

def search(m, event, out=None):
    global excludelist
    global urllist
    global ticket_id
    global event_tag
    global event_name
    result = m.get_event(event)
    if out is None:
        event_name = result['Event']["info"].replace('\r\n','')
        event_id   = result['Event']["id"]
        event_tag  = result['Event']["Tag"][0]["name"]
        not_white = True
        for eventtag in result['Event']["Tag"]:
            event_tag = eventtag["name"]
            if eventtag["name"] == "tlp:white":
                not_white = False
                event_tag = eventtag["name"]
                break
        if not_white is True: 
            print "Attention! This MISP event is not TLP:WHITE!"
            print "Make sure you are allowed to handle this event."
            input = raw_input("Continue? (y/N) ") or "n"
            if input == "y" or input == "Y":
                print " Continuing..."
            else:
                print " Aborting."
                sys.exit(0)
        attribute = result['Event']["Attribute"]
        for e in attribute:
            if e['type'] == "url":
                isExcluded = False
                for excl in excludelist:
                    if excl in e['value']:
                        isExcluded = True
                if not isExcluded:
                    urllist.append(e['value'])
        attribute = result['Event']["ShadowAttribute"]
        for e in attribute:
            if e['type'] == "url":
                isExcluded = False
                for excl in excludelist:
                    if excl in e['value']:
                        isExcluded = True
                if not isExcluded:
                    urllist.append(e['value'])
    else:
        print('No results for that time period')
        exit(0)

form_data = 0 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download events from a MISP instance (with filters).')
    parser.add_argument("-e", "--event", required=True, help="specify an event id")
    args = parser.parse_args()
    misp = init(misp_url, misp_key)
    search(misp, args.event)

# Initial data for the form
form_data = {
    "MID": args.event,
    "ENA": event_name,
    "ETA": event_tag,
    "onlinecheck": True,
}
for entry in urllist:
    form_data.update({entry:True})

class DemoFrame(Frame):
    def __init__(self, screen):
        self.screen = screen
        super(DemoFrame, self).__init__(screen,
                                        int(screen.height),
                                        int(screen.width),
                                        data=form_data,
                                        has_shadow=True,
                                        has_border=True,
                                        name="My Form",
                                        x=0, y=0,)
        layout = Layout([1], fill_frame=False)
        self.add_layout(layout)
        self._reset_button = Button("Reset", self._reset)
        title = "MISP Event #{} ({}):".format(args.event, event_tag)
        layout.add_widget(
            Text(label=title, name="ENA", on_change=self._on_change), 0)
        layout.add_widget(Divider(height=1), 0)
        layout1 = Layout([1,1], fill_frame=False)
        self.add_layout(layout1)
        layout1.add_widget(RadioButtons([("Malicious files hosted", 1),
                                        ("Compromised server", 2)],
                                       label="Templates",
                                       name="template",
                                       on_change=self._on_change), 0)
        dryruntext = "Dry-run (all mails to %s)" % override_email    
        layout1.add_widget(CheckBox(dryruntext, name="dryrun", on_change=self._on_change),1)
        onlinechecktext = "Verify resource (online and size > %s bytes)" % min_size    
        layout1.add_widget(CheckBox(onlinechecktext, name="onlinecheck", on_change=self._on_change),1)
        layout2 = Layout([50,50], fill_frame=True)
        self.add_layout(layout2)
        layout2.add_widget(Divider(height=1), 0)
        layout2.add_widget(Divider(height=1), 1)
        layout2.fix(0,0,0,5)
        i=False
        for entry in urllist:
            if i is False: 
                layout2.add_widget(CheckBox(entry, name=entry, on_change=self._on_change), 0)
                i = True
            else:
                layout2.add_widget(CheckBox(entry, name=entry, on_change=self._on_change), 1)
                i = False 
        self.l = layout2
        layout4 = Layout([1,1,1])
        self.add_layout(layout4)
        layout4.add_widget(self._reset_button, 0)
        layout4.add_widget(Button("Quit", self._quit), 1)
        layout4.add_widget(Button("Process data", self._process), 2)
        self.fix()

    def _on_change(self):
        changed = False
        self.save()
        for key, value in self.data.items():
            if key not in form_data or form_data[key] != value:
                changed = True
                break
        self._reset_button.disabled = not changed

    def _reset(self):
        self.reset()
        raise NextScene()

    def _process(self):
        global queueLock
        global workQueue
        global event_name
        global logsize
        urls_to_process = []
        template_file = ""
        email_override = False
        onlinecheck = True
        # Build result of this form and display it.
        self.save()
        for key, value in self.data.items():
            if key is 'template':
                if value is 1:
                    template_file = "templates/malicious_files_hosted.tmpl"
                if value is 2:
                    template_file = "templates/compromised_website.tmpl"
            if key is 'dryrun':
                if value is True:
                    email_override = True
            if key is 'onlinecheck':
                if value is False:
                    onlinecheck = False
                    
            if key is 'ENA':
                event_name = value
        
            if (isinstance(value, bool) and value is True and key is not 'onlinecheck'):
                urls_to_process.append(key)
        
        incident = create_ticket(args.event, event_name)

        # Establish communication queues
        tasks = multiprocessing.JoinableQueue()
        results = multiprocessing.Queue()
        num_jobs = len(urls_to_process)
      
        # Start consumers
        num_consumers = len(urls_to_process) 
        consumers = [ Consumer(tasks, results) for i in xrange(num_consumers) ]        
        for w in consumers:
            w.start()

        # Ringbuffer for log output 
        logsize = self.screen.height - 10
        d = collections.deque(maxlen=logsize)

        # Enqueue jobs
        for url in urls_to_process:
            logline = "Adding task for: %s" % url
            log(d, self.screen, self.l, logline, 8, self.screen.height)
            tasks.put(Task(incident, template_file, url, email_override, onlinecheck))
        
        log(d, self.screen, self.l, "Processing, please wait...", 8, self.screen.height)
        # Add a poison pill for each consumer
        for i in xrange(num_consumers):
            tasks.put(None)

        # Wait for all of the tasks to finish
        tasks.join()
    
        # Start printing results
        while num_jobs:
            result = results.get()
            logline = "Result: %s" % result
            log(d, self.screen, self.l, logline, 8, self.screen.height)
            num_jobs -= 1
        log(d, self.screen, self.l, "Finished. Please a key to continue.", 8, self.screen.height)
        while True:
            key = self.screen.get_event()
            if key and isinstance(key, KeyboardEvent):
                break    

    def _quit(self):
        self._scene.add_effect(
            PopUpDialog(self._screen,
                        "Are you sure?",
                        ["Yes", "No"],
                        on_close=self._quit_on_yes))

    @staticmethod
    def _quit_on_yes(selected):
        # Yes is the first button
        if selected == 0:
            raise StopApplication("User requested exit")


# Event handler for global keys
def global_shortcuts(event):
    if isinstance(event, KeyboardEvent):
        c = event.key_code
        # Stop on ctrl+q or ctrl+x
        if c in (17, 24):
            # fix this to call quit()
            raise StopApplication("User terminated app")


def demo(screen, scene):
    scenes = []
    effects = [
        DemoFrame(screen),
    ]
    scenes.append(Scene(effects, -1))

    screen.play(scenes, stop_on_resize=True, start_scene=scene, unhandled_input=global_shortcuts)

last_scene = None
while True:
    try:
        Screen.wrapper(demo, catch_interrupt=False, arguments=[last_scene])
        sys.exit(0)
    except ResizeScreenError as e:
        last_scene = e.scene
